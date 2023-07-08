module com.example.filecryptoapplication {
    requires javafx.controls;
    requires javafx.fxml;
            
        requires org.controlsfx.controls;
                        requires org.kordamp.bootstrapfx.core;
    requires json.simple;

    opens com.example.filecryptoapplication to javafx.fxml;
    exports com.example.filecryptoapplication;
}