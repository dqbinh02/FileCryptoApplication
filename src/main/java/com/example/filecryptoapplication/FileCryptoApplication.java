package com.example.filecryptoapplication;

import javafx.application.Application;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.input.Clipboard;
import javafx.scene.input.ClipboardContent;
import javafx.scene.layout.BorderPane;
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
        BorderPane layout = new BorderPane();

        Button encryptModeButton = new Button("Encryption");
        encryptModeButton.setId("encryptModeButton");
        Button decryptModeButton = new Button("Decryption");
        decryptModeButton.setId("decryptModeButton");
        Button openAFilePlaintextButton = new Button("Choose a file plaintext");
        Button openAFileCButton = new Button("Choose a file C");
        Button openFileKeyPrivateButton = new Button("Choose file K private");

        layout.setLeft(encryptModeButton);
        layout.setRight(decryptModeButton);
        BorderPane.setAlignment(encryptModeButton, Pos.CENTER);
        BorderPane.setAlignment(decryptModeButton, Pos.CENTER);
        BorderPane.setMargin(encryptModeButton, new Insets(100));
        BorderPane.setMargin(decryptModeButton, new Insets(100));

        Scene scene = new Scene(layout, 960, 720);
//        scene.getStylesheets().add(Objects.requireNonNull(getClass().getResource("styles.css")).toExternalForm());
        stage.setTitle("Cryptography");
        stage.setScene(scene);
        stage.show();


        encryptModeButton.setOnAction(actionEvent -> {
            plaintextFile = null;

            layout.getChildren().removeIf(node -> node instanceof Button);

            Button startEncryptButton = new Button("Start Encrypt");
            startEncryptButton.setId("startEncryptButton");

            VBox buttonContainer = new VBox();
            buttonContainer.setAlignment(Pos.CENTER);
            buttonContainer.setSpacing(10);
            buttonContainer.getChildren().addAll(openAFilePlaintextButton, startEncryptButton);

            VBox.setMargin(startEncryptButton, new Insets(40, 0, 0, 0));

            layout.setCenter(buttonContainer);

//            scene.getStylesheets().add(Objects.requireNonNull(getClass().getResource("encryptMode.css")).toExternalForm());

            openAFilePlaintextButton.setOnAction(actionEvent1 -> {
                FileChooser fileChooser = new FileChooser();
                fileChooser.setTitle("Open a file");
                fileChooser.setInitialDirectory(new File("/home/"));
                plaintextFile = fileChooser.showOpenDialog(stage);
                if (plaintextFile!=null){
                    openAFilePlaintextButton.setText(plaintextFile.getName());
                }else {
                    openAFilePlaintextButton.setText("File not selected");
                }
            });

            /// Start encrypt
            startEncryptButton.setOnAction(actionEvent1 -> {
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

                    ScrollPane scrollPane = new ScrollPane(privateKeyLabel);
                    scrollPane.setFitToHeight(true);
                    scrollPane.setFitToWidth(true);
                    layout.setBottom(scrollPane);

                    // Create copy button
                    Button copyButton = new Button("Copy");
                    copyButton.setOnAction(event -> {
                        String textToCopy = privateKeyLabel.getText();
                        Clipboard clipboard = Clipboard.getSystemClipboard();
                        ClipboardContent content = new ClipboardContent();
                        content.putString(textToCopy);
                        clipboard.setContent(content);
                    });
                    layout.setTop(copyButton);

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
        });

        decryptModeButton.setOnAction(actionEvent -> {
            CFile = null;
            KprivateFile = null;

            layout.getChildren().removeIf(node -> node instanceof Button);

            Button startDecryptButton = new Button("Start Decrypt");
            startDecryptButton.setId("startDecryptButton");

            VBox buttonContainer = new VBox();
            buttonContainer.setAlignment(Pos.CENTER);
            buttonContainer.setSpacing(10);
            buttonContainer.getChildren().addAll(openAFileCButton, openFileKeyPrivateButton, startDecryptButton);
            VBox.setMargin(openFileKeyPrivateButton, new Insets(40, 0, 0, 0));
            VBox.setMargin(startDecryptButton, new Insets(40, 0, 0, 0));
            layout.setCenter(buttonContainer);
//            scene.getStylesheets().add(Objects.requireNonNull(getClass().getResource("decryptMode.css")).toExternalForm());


            openAFileCButton.setOnAction(actionEvent1 -> {
                FileChooser fileChooser = new FileChooser();
                fileChooser.setTitle("Open a file");
                fileChooser.setInitialDirectory(new File("/home/"));
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
                fileChooser.setInitialDirectory(new File("/home/"));
                KprivateFile = fileChooser.showOpenDialog(stage);
                if (KprivateFile!=null){
                    openFileKeyPrivateButton.setText(KprivateFile.getName());
                }else {
                    openFileKeyPrivateButton.setText("File not selected");
                }
            });

            startDecryptButton.setOnAction(actionEvent1 -> {
                if (CFile == null && KprivateFile==null){
                    System.out.println("Please choose file");
                }else{
                    //
                    byte[] ciphertextBytes = null;
                    byte[] KxBytes = null;
                    byte[] HKPrivateBytes = null;
                    JSONParser jsonParser = new JSONParser();
                    try(FileReader reader = new FileReader(CFile)){
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
                    try {
                        KPrivateBytes = Base64.getDecoder().decode(new String(Files.readAllBytes(KprivateFile.toPath())));
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                    //

                    if(ciphertextBytes==null || KxBytes ==null || HKPrivateBytes==null){

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
                            String decryptString = new String(plaintextBytes);
                            System.out.println(decryptString);
                        }else {
                            System.out.println("Not equal hash kprivate");
                        }
                    }
                }
            });
        });

    }

    public static void main(String[] args) {
        launch();
    }
}