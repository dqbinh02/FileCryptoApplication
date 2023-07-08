package com.example.filecryptoapplication;

import javafx.application.Application;
import javafx.event.Event;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.input.Clipboard;
import javafx.scene.input.ClipboardContent;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import java.io.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import java.io.File;
import java.nio.file.Files;
import java.security.*;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

class CryptionModule {
    private static final String AES_ALGORITHM = "AES";
    private static final String RSA_ALGORITHM = "RSA";
    private static final String SHA1_ALGORITHM = "SHA-1";
    private static final String SHA256_ALGORITHM = "SHA-256";

    private SecretKey generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(AES_ALGORITHM);
        keyGenerator.init(128); // AES key size
        return keyGenerator.generateKey();
    }

    public SecretKey generateSecretKey() throws NoSuchAlgorithmException {
        return generateAESKey();
    }

    public byte[] encryptAES(byte[] fileData, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(fileData);
    }

    public byte[] decryptAES(byte[] encryptedData, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return cipher.doFinal(encryptedData);
    }

    public KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        SecureRandom secureRandom = new SecureRandom();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA_ALGORITHM);
        keyPairGenerator.initialize(2048,secureRandom); // RSA key size
        return keyPairGenerator.generateKeyPair();
    }

    public byte[] encryptRSA(byte[] plaintext, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(plaintext);
    }

    public byte[] decryptRSA(byte[] ciphertext, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(ciphertext);
    }

    public byte[] calculateHash(byte[] plaintext, String algorithm) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance(algorithm);
        messageDigest.update(plaintext);
        return messageDigest.digest();
    }
}

public class FileCryptoApplication extends Application {
    private File plaintextFile;
    private File CFile;
    private File KprivateFile;
    @Override
    public void start(Stage stage) throws IOException {
        // create scene graph
        BorderPane layout = new BorderPane();
        VBox taskbar = new VBox();
        VBox bodyEncrypt = new VBox();
        VBox bodyDecrypt = new VBox();
        layout.setLeft(taskbar);

        // Node of taskbar
        Button encryptModeButton = new Button("Encryption");
        encryptModeButton.setId("encryptModeButton");
        Button decryptModeButton = new Button("Decryption");
        decryptModeButton.setId("decryptModeButton");

        // Node of encrypted mode
        Button openAFilePlaintextButton = new Button("Choose a file plaintext");
        Button startEncryptButton = new Button("Start Encrypt");
        ScrollPane showPrivateKeyScrollPane = new ScrollPane();
        Button copyButton = new Button("Copy");

        // Node of decrypted mode
        Button openAFileCButton = new Button("Choose a file C");
        TextField fieldKPrivate = new TextField();
        ScrollPane typePrivateKeyScrollPane = new ScrollPane(fieldKPrivate);
        Button openFileKeyPrivateButton = new Button("Choose file K private");
        Button startDecryptButton = new Button("Start Decrypt");

        // add node to group
        taskbar.getChildren().addAll(encryptModeButton,decryptModeButton);
        bodyEncrypt.getChildren().addAll(openAFilePlaintextButton, startEncryptButton, showPrivateKeyScrollPane, copyButton);
        bodyDecrypt.getChildren().addAll(openAFileCButton, typePrivateKeyScrollPane, openFileKeyPrivateButton, startDecryptButton);

        // UI task bar
        taskbar.setStyle("-fx-background-color: #164804");
        taskbar.setSpacing(50);
        taskbar.setAlignment(Pos.TOP_CENTER);
        taskbar.setPadding(new Insets(50,50,10,50));
        decryptModeButton.setPrefSize(200,75);
        encryptModeButton.setPrefSize(200,75);

        // Ui body
        bodyEncrypt.setSpacing(100);
        bodyEncrypt.setAlignment(Pos.CENTER);
        bodyDecrypt.setSpacing(100);
        bodyDecrypt.setAlignment(Pos.CENTER);
        // tạm thời đặt để đưa vào css file sau
        openAFilePlaintextButton.setPrefSize(200,100);
        startEncryptButton.setPrefSize(200,100);
        openAFileCButton.setPrefSize(200,100);
        openFileKeyPrivateButton.setPrefSize(200,100);
        startDecryptButton.setPrefSize(200,100);
        showPrivateKeyScrollPane.setFitToHeight(true);
        showPrivateKeyScrollPane.setFitToWidth(true);


//        scene.getStylesheets().add(Objects.requireNonNull(getClass().getResource("styles.css")).toExternalForm());
        Scene scene = new Scene(layout, 960, 720);
        stage.setTitle("Cryptography");
        stage.setScene(scene);
        stage.show();

        encryptModeButton.setOnAction(actionEvent -> {
            layout.setCenter(bodyEncrypt);
        });
        encryptModeButton.fire();

        decryptModeButton.setOnAction(actionEvent -> {
            layout.setCenter(bodyDecrypt);
        });

        openAFilePlaintextButton.setOnAction(actionEvent -> {
            FileChooser fileChooser = new FileChooser();
            fileChooser.setTitle("Open a file");
            fileChooser.setInitialDirectory(new File("/"));
            plaintextFile = fileChooser.showOpenDialog(stage);
            if (plaintextFile!=null){
                openAFilePlaintextButton.setText(plaintextFile.getName());
            }else {
                openAFilePlaintextButton.setText("File not selected");
            }
        });

        openAFileCButton.setOnAction(actionEvent1 -> {
            FileChooser fileChooser = new FileChooser();
            fileChooser.setTitle("Open a file");
            fileChooser.setInitialDirectory(new File("/"));
            CFile = fileChooser.showOpenDialog(stage);
            if (CFile!=null){
                openAFileCButton.setText(CFile.getName());
            }else {
                openAFileCButton.setText("File not selected");
            }
        });

        openFileKeyPrivateButton.setOnAction(actionEvent1 -> {
            FileChooser fileChooser = new FileChooser();
            fileChooser.setTitle("Open a file");
            fileChooser.setInitialDirectory(new File("/"));
            KprivateFile = fileChooser.showOpenDialog(stage);
            if (KprivateFile!=null){
                openFileKeyPrivateButton.setText(KprivateFile.getName());
            }else {
                openFileKeyPrivateButton.setText("File not selected");
            }
        });

        startEncryptButton.setOnAction(actionEvent -> {
            if (plaintextFile == null) {
                System.out.println("Please choose file");
            }else{
                CryptionModule module = new CryptionModule();
                // Generate secret key
                SecretKey secretKey = null;
                try {
                    secretKey = module.generateSecretKey();
                } catch (NoSuchAlgorithmException e) {
                    throw new RuntimeException(e);
                }

                // Encrypt file using AES
                byte[] fileData = new byte[0];
                byte[] ciphertextBytes;
                try {
                    fileData = Files.readAllBytes(plaintextFile.toPath());
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
                try {
                    ciphertextBytes = module.encryptAES(fileData, secretKey);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }

                // Generate RSA key pair
                KeyPair keyPair = null;
                try {
                    keyPair = module.generateRSAKeyPair();
                } catch (NoSuchAlgorithmException e) {
                    throw new RuntimeException(e);
                }

                // Encrypt Ks using RSA public key to Kx
                byte[] KxBytes;
                try {
                    KxBytes = module.encryptRSA(secretKey.getEncoded(), keyPair.getPublic());
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }

                // SHA-1 Key private to HKPrivate
                byte[]  HKPrivateBytes;
                try {
                    HKPrivateBytes = module.calculateHash(keyPair.getPrivate().getEncoded(),"SHA-1");
                } catch (NoSuchAlgorithmException e) {
                    throw new RuntimeException(e);
                }

                // Save to file
                // create jsonObject
                JSONObject jsonObject = new JSONObject();
                jsonObject.put("ciphertextBytes", Base64.getEncoder().encodeToString(ciphertextBytes));
                jsonObject.put("KxBytes", Base64.getEncoder().encodeToString(KxBytes));
                jsonObject.put("HKPrivateBytes", Base64.getEncoder().encodeToString(HKPrivateBytes));
                JSONArray jsonArray = new JSONArray();
                jsonArray.add(jsonObject);
                try{
                    // Write the JSON array to a file
                    FileWriter fileWriter = new FileWriter("C.json");
                    fileWriter.write(jsonArray.toJSONString());
                    fileWriter.close();
                }catch (IOException e){
                    e.printStackTrace();
                }

                // Export key Private for user
                Label privateKeyLabel = new Label(Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()));
                privateKeyLabel.setWrapText(true);
                showPrivateKeyScrollPane.setContent(privateKeyLabel);


                // copy button
                copyButton.setOnAction(event -> {
                    String textToCopy = privateKeyLabel.getText();
                    Clipboard clipboard = Clipboard.getSystemClipboard();
                    ClipboardContent content = new ClipboardContent();
                    content.putString(textToCopy);
                    clipboard.setContent(content);
                });

                // save key private to file
                try{
                    // Write the key private to a file
                    FileWriter fileWriter = new FileWriter("KPrivate_Base64.txt");
                    fileWriter.write(Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()));
                    fileWriter.close();
                }catch (IOException e){
                    e.printStackTrace();
                }
            }
        });

        startDecryptButton.setOnAction(actionEvent1 -> {
            if (CFile == null && KprivateFile==null){
                System.out.println("Please choose file");
            }else{
                byte[] ciphertextBytes = null;
                byte[] KxBytes = null;
                byte[] HKPrivateBytes = null;
                JSONParser jsonParser = new JSONParser();
                try(FileReader reader = new FileReader(CFile != null ? CFile : null)){
                    Object obj = jsonParser.parse(reader);
                    JSONArray jsonArray = (JSONArray) obj;
                    for (Object o : jsonArray) {
                        JSONObject jsonObject = (JSONObject) o;
                        ciphertextBytes = Base64.getDecoder().decode((String)jsonObject.get("ciphertextBytes"));
                        KxBytes = Base64.getDecoder().decode((String) jsonObject.get("KxBytes"));
                        HKPrivateBytes = Base64.getDecoder().decode((String) jsonObject.get("HKPrivateBytes"));
                    }
                } catch (ParseException e) {
                    throw new RuntimeException(e);
                } catch (FileNotFoundException e) {
                    throw new RuntimeException(e);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }

                byte[] KPrivateBytes = new byte[0];
                String text = fieldKPrivate.getText();

                if (text.trim().isEmpty()) {
                    try {
                        KPrivateBytes = Base64.getDecoder().decode(new String(Files.readAllBytes(KprivateFile.toPath())));
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                }else{
                    KPrivateBytes = Base64.getDecoder().decode(text);
                }

                if(ciphertextBytes==null || KxBytes ==null || HKPrivateBytes==null){
                    //////////////////////////////////////////////////////
                }else {
                    CryptionModule module = new CryptionModule();
                    byte[] hashKPrivateBytes;
                    try {
                        hashKPrivateBytes = module.calculateHash(KPrivateBytes,"SHA-1");
                    } catch (NoSuchAlgorithmException e) {
                        throw new RuntimeException(e);
                    }
                    if(Arrays.equals(hashKPrivateBytes,HKPrivateBytes)){
                        KeyFactory keyFactory = null;
                        try {
                            keyFactory = KeyFactory.getInstance("RSA");
                        } catch (NoSuchAlgorithmException e) {
                            throw new RuntimeException(e);
                        }
                        PrivateKey privateKey;
                        try {
                            privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(KPrivateBytes));
                        } catch (InvalidKeySpecException e) {
                            throw new RuntimeException(e);
                        }
                        byte[] KsBytes;
                        try {
                            KsBytes = module.decryptRSA(KxBytes, privateKey);
                        } catch (Exception e) {
                            throw new RuntimeException(e);
                        }

                        SecretKey KsSecretKey = new SecretKeySpec(KsBytes,"AES");
                        byte[] plaintextBytes;
                        try {
                            plaintextBytes = module.decryptAES(ciphertextBytes,KsSecretKey);
                        } catch (Exception e) {
                            throw new RuntimeException(e);
                        }

                        try{
                            FileOutputStream exportFile = new FileOutputStream("data");
                            exportFile.write(plaintextBytes);
                            exportFile.close();
                            System.out.println("saved file !");
                        }catch (IOException e){
                            e.printStackTrace();
                        }
                    }else {
                        System.out.println("Not equal hash k private");
                    }
                }
            }
        });
    }

    public static void main(String[] args) {
        launch();
    }
}