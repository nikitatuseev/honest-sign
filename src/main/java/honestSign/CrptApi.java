package honestSign;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class CrptApi {

    private static final String AUTH_PATH = "/api/v3/auth/cert/key"; // Путь к ресурсу для аутентификации
    private static final String TOKEN_PATH = "/api/v3/auth/cert/"; // Путь к ресурсу для получения токена
    private static final String CREATE_DOC = "/api/v3/lk/documents/send"; // Путь к ресурсу для создания документа товара
    private static final String BASE_URL = "https://ismp.crpt.ru"; // Базовый URL для всех запросов

    private final BlockingQueue<Object> requestQueue; // Очередь для запросов
    private final ObjectMapper mapper = new ObjectMapper(); // Объект для сериализации/десериализации JSON
    private final Lock lock = new ReentrantLock(); // Семафор для синхронизации
    private final HttpClient httpClient; // Объект для выполнения HTTP-запросов
    private final TimeUnit timeUnit;
    private final int requestLimit;


    // Конструктор класса, принимающий TimeUnit и requestLimit, что позволяет задать ограничение на количество запросов в определенном промежутке времени.
    public CrptApi(TimeUnit timeUnit, int requestLimit) {
        this.requestQueue = new LinkedBlockingQueue<>();
        this.timeUnit = timeUnit;
        this.requestLimit = requestLimit;

        httpClient = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_2)
                .connectTimeout(timeUnit.toChronoUnit().getDuration())
                .build();
    }

    // Метод documentCreation предназначен для создания документа и отправки запроса к АПИ. Метод обрабатывает ошибки и выбрасывает CrptApiException в случае ошибки.
    public Object documentCreation(Object document, String signature) throws CrptApiException {
        try {
            AuthData authResponse = authRequest();
            String data = signData(signature, authResponse.getData());
            Token token = getAuthToken(new AuthData(authResponse.getUuid(), data));
            Document pojoDoc = convertObjectToDocument(document, signature);

            enqueue(createDocRequest(pojoDoc, token));

            return dequeue();
        } catch (IOException | InterruptedException |
                 NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                 IllegalBlockSizeException | BadPaddingException e) {
            throw new CrptApiException("Error in document creation: " + e.getMessage(), e);
        }
    }

    // Метод createDocRequest отправляет запрос к АПИ для создания документа и возвращает ответ. Обрабатывает ошибки, и выбрасывает исключение.
    private DocumentResponse createDocRequest(Document doc, Token token) throws IOException, InterruptedException {
        lock.lock();
        try {
            String jsonBody = mapper.writeValueAsString(doc);
            HttpRequest httpRequest = HttpRequest.newBuilder()
                    .uri(URI.create(BASE_URL + CREATE_DOC))
                    .header("Authorization", "Bearer " + token.getToken())
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
                    .build();
            HttpResponse<String> response = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString());
            return mapper.readValue(response.body(), DocumentResponse.class);
        } finally {
            lock.unlock();
        }
    }

    // Метод authRequest отправляет запрос на аутентификацию и возвращает AuthData, которые содержат необходимые данные для дальнейших операций.
    private AuthData authRequest() throws IOException, InterruptedException {
        lock.lock();
        try {
            HttpRequest httpRequest = HttpRequest.newBuilder()
                    .uri(URI.create(BASE_URL + AUTH_PATH))
                    .GET()
                    .build();
            HttpResponse<String> response = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString());
            return mapper.readValue(response.body(), AuthData.class);
        } finally {
            lock.unlock();
        }
    }

    // Метод getAuthToken отправляет запрос для получения токена и возвращает его для последующих запросов.
    private Token getAuthToken(AuthData data) throws IOException, InterruptedException {
        lock.lock();
        try {
            String jsonBody = mapper.writeValueAsString(data);
            HttpRequest httpRequest = HttpRequest.newBuilder()
                    .uri(URI.create(BASE_URL + TOKEN_PATH))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
                    .build();
            HttpResponse<String> response = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString());
            return mapper.readValue(response.body(), Token.class);
        } finally {
            lock.unlock();
        }
    }

    // Метод enqueue добавляет элемент в очередь запросов, при этом учитывает ограничение на количество запросов в определенном промежутке времени.
    public void enqueue(Object item) throws CrptApiException {
        try {
            while (requestQueue.size() >= requestLimit) {
                Thread.sleep(timeUnit.toChronoUnit().getDuration().getSeconds());
            }
            requestQueue.put(item);
        } catch (InterruptedException e) {
            throw new CrptApiException("Error in enqueue: " + e.getMessage(), e);
        }
    }

    // Метод dequeue извлекает элемент из очереди запросов и обрабатывает возможные ошибки.
    public Object dequeue() throws CrptApiException {
        try {
            return requestQueue.take();
        } catch (InterruptedException e) {
            throw new CrptApiException("Error in dequeue: " + e.getMessage(), e);
        }
    }

    // Метод convertObjectToDocument конвертирует входные данные в формат Document и добавляет подпись.
    private Document convertObjectToDocument(Object document, String signature) throws JsonProcessingException {
        Document pojoDoc = mapper.readValue(document.toString(), Document.class);
        pojoDoc.setSignature(encode(signature.getBytes()));

        return pojoDoc;
    }

    // Метод signData выполняет подпись данных с использованием шифрования.ё
    private String signData(String signature, String data) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec spec = new SecretKeySpec(signature.getBytes(StandardCharsets.UTF_8), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, spec);
        byte[] bytes = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));

        return encode(bytes);
    }

    // Метод encode кодирует байты в строку в формате Base64.
    private String encode(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    // Внутренний класс CrptApiException используется для обработки ошибок в методах класса.
    public static class CrptApiException extends Exception {
        public CrptApiException(String message) {
            super(message);
        }

        public CrptApiException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    // Внутренний класс AuthData используется для хранения данных аутентификации и содержит геттеры и сеттеры для доступа к полям.
    public static class AuthData {
        private String uuid;
        private String data;

        public AuthData() {
        }

        public AuthData(String uuid, String data) {
            this.uuid = uuid;
            this.data = data;
        }

        public String getUuid() {
            return uuid;
        }

        public void setUuid(String uuid) {
            this.uuid = uuid;
        }

        public String getData() {
            return data;
        }

        public void setData(String data) {
            this.data = data;
        }
    }

    // Внутренний класс Token используется для хранения токена и также содержит геттеры и сеттеры для доступа к полю.
    public static class Token {
        private String token;

        public Token() {
        }

        public Token(String token) {
            this.token = token;
        }

        public String getToken() {
            return token;
        }

        public void setToken(String token) {
            this.token = token;
        }
    }

    // Внутренний класс DocumentResponse используется для хранения ответа от АПИ и предоставляет геттеры и сеттеры для доступа к данным.
    public static class DocumentResponse {
        private String value;

        public DocumentResponse() {
        }

        public DocumentResponse(String value) {
            this.value = value;
        }

        public String getValue() {
            return value;
        }

        public void setValue(String value) {
            this.value = value;
        }
    }

    // Внутренний класс Document используется для представления документа и предоставляет геттеры и сеттеры для доступа к полям.
    public static class Document {
        private String documentFormat;
        private String productDocument;
        private String productGroup;
        private String signature;
        private String type;

        public Document() {
        }

        public Document(String documentFormat, String productDocument, String productGroup, String signature, String type) {
            this.documentFormat = documentFormat;
            this.productDocument = productDocument;
            this.productGroup = productGroup;
            this.signature = signature;
            this.type = type;
        }

        public String getDocumentFormat() {
            return documentFormat;
        }

        public void setDocumentFormat(String documentFormat) {
            this.documentFormat = documentFormat;
        }

        public String getProductDocument() {
            return productDocument;
        }

        public void setProductDocument(String productDocument) {
            this.productDocument = productDocument;
        }

        public String getProductGroup() {
            return productGroup;
        }

        public void setProductGroup(String productGroup) {
            this.productGroup = productGroup;
        }

        public String getSignature() {
            return signature;
        }

        public void setSignature(String signature) {
            this.signature = signature;
        }

        public String getType() {
            return type;
        }

        public void setType(String type) {
            this.type = type;
        }
    }
}