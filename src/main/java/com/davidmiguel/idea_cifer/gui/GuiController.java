package com.davidmiguel.idea_cifer.gui;

import java.io.File;
import java.io.IOException;

import com.davidmiguel.idea_cifer.modes.FileCipher;
import com.davidmiguel.idea_cifer.modes.OperationMode;
import javafx.scene.control.*;
import javafx.stage.Stage;

import javafx.fxml.FXML;
import javafx.scene.control.Alert.AlertType;
import javafx.stage.FileChooser;

public class GuiController {

    @FXML
    private ToggleGroup operation;
    @FXML
    private ToggleGroup operationMenu;
    @FXML
    private ToggleGroup operationMode;
    @FXML
    private ToggleGroup operationModeMenu;
    @FXML
    private TextField inputFile;
    @FXML
    private TextField outputFile;
    @FXML
    private RadioButton encrypt;
    @FXML
    private RadioMenuItem encryptMenu;
    @FXML
    private RadioButton decrypt;
    @FXML
    private RadioMenuItem decryptMenu;
    @FXML
    private RadioButton ecb;
    @FXML
    private RadioMenuItem ecbMenu;
    @FXML
    private RadioButton cbc;
    @FXML
    private RadioMenuItem cbcMenu;
    @FXML
    private RadioButton cfb;
    @FXML
    private RadioMenuItem cfbMenu;
    @FXML
    private RadioButton ofb;
    @FXML
    private RadioMenuItem ofbMenu;
    @FXML
    private PasswordField key;
    @FXML
    private TextArea status;
    @FXML
    private ProgressBar progressBar;

    private File input;
    private File output;

    @FXML
    private void initialize() {
        operation.selectedToggleProperty().addListener((observable, oldValue, newValue) -> {
            handleSelectRadio(operation, operationMenu);
        });
        operationMenu.selectedToggleProperty().addListener(observable -> {
            handleSelectRadio(operationMenu, operation);
        });
        operationMode.selectedToggleProperty().addListener((observable, oldValue, newValue) -> {
            handleSelectRadio(operationMode, operationModeMenu);
        });
        operationModeMenu.selectedToggleProperty().addListener((observable, oldValue, newValue) -> {
            handleSelectRadio(operationModeMenu, operationMode);
        });
        // Set userDir as default output
        output = new File(System.getProperty("user.home"));
        outputFile.setText(output.toString().replace("\\", "/"));
        inputFile.setText(output.toString().replace("\\", "/"));
    }

    /**
     * Menu file. Select input file.
     */
    @FXML
    private void handleSelectInput() {
        input = selectFile(true, "Select input");
        if (input != null) {
            inputFile.setText(input.toString().replace("\\", "/"));
        }
    }

    /**
     * Menu file. Select output file.
     */
    @FXML
    private void handleSelectOutput() {
        output = selectFile(false, "Select output");
        if (input != null) {
            outputFile.setText(output.toString().replace("\\", "/"));
        }
    }

    /**
     * Run cipher.
     */
    @FXML
    private void handleRun() {
        if (input == null || !input.isFile() || output == null) {
            showError("no-file");
            return;
        } else if (key.getText().equals("")) {
            showError("no-key");
            return;
        }
        System.out.println((((RadioButton) operation.getSelectedToggle()).getText()));
        boolean encrypt = (((RadioButton) operation.getSelectedToggle()).getText()).equals("Encrypt");
        OperationMode.Mode mode = null;
        switch (((RadioButton) operationMode.getSelectedToggle()).getText()) {
            case "ECB":
                mode = OperationMode.Mode.ECB;
                break;
            case "CBC":
                mode = OperationMode.Mode.CBC;
                break;
            case "CFB":
                mode = OperationMode.Mode.CFB;
                break;
            case "OFB":
                mode = OperationMode.Mode.OFB;
                break;
        }
        try {
            FileCipher.cryptFile(input.getPath(), output.getPath(),
                    key.getText(), encrypt, mode);
        } catch (IOException e) {
            status.appendText("Error: " + e.getMessage() + "\n");
            e.printStackTrace();
        }
    }

    /**
     * Menu file. Closes the application.
     */
    @FXML
    private void handleClose() {
        System.exit(0);
    }

    /**
     * Show author info.
     */
    @FXML
    private void handleAbout() {
        Alert alert = new Alert(AlertType.INFORMATION);
        alert.setTitle("IDEA cipher");
        alert.setHeaderText("About");
        alert.setContentText("Author: David Miguel\nWebsite: http://davidmiguel.com/");
        alert.showAndWait();
    }

    private void handleSelectRadio(ToggleGroup group, ToggleGroup groupToUpdate) {
        String selected = null;
        for (Toggle t : group.getToggles()) {
            if (t.isSelected()) {
                selected = t instanceof RadioButton ? ((RadioButton) t).getText() : ((RadioMenuItem) t).getText();
                break;
            }
        }
        for (Toggle t : groupToUpdate.getToggles()) {
            String text = t instanceof RadioButton ? ((RadioButton) t).getText() : ((RadioMenuItem) t).getText();
            if (text.equals(selected)) {
                groupToUpdate.selectToggle(t);
            }
        }
    }

    private File selectFile(boolean open, String title) {
        Stage primaryStage = (Stage) inputFile.getScene().getWindow();
        FileChooser fileChooser = new FileChooser();
        fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("All files (*.*)", "*.*"));
        fileChooser.setInitialDirectory(new File(System.getProperty("user.home")));
        fileChooser.setTitle(title);
        return open ? fileChooser.showOpenDialog(primaryStage) : fileChooser.showSaveDialog(primaryStage);
    }

    private void showError(String error) {
        Alert alert = new Alert(AlertType.ERROR);
        alert.setTitle("Error");
        if (error.equals("no-file")) {
            alert.setHeaderText("No file chosen");
            alert.setContentText("You have to choose the file to encrypt.");
        } else if (error.equals("no-key")) {
            alert.setHeaderText("No key");
            alert.setContentText("You have to enter a key.");
        }
        alert.showAndWait();
    }
}