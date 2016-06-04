package com.davidmiguel.idea_cipher.gui;

import java.io.File;

import com.davidmiguel.idea_cipher.modes.FileCipher;
import com.davidmiguel.idea_cipher.modes.OperationMode;
import javafx.application.Platform;
import javafx.concurrent.Worker;
import javafx.scene.control.*;
import javafx.stage.Stage;

import javafx.fxml.FXML;
import javafx.scene.control.Alert.AlertType;
import javafx.stage.FileChooser;

/**
 * Controller for the GUI.
 */
public class GuiController {

    @FXML
    private Button selInput;
    @FXML
    private Button selOutput;
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
    private Button run;
    @FXML
    private MenuItem runMenu;
    @FXML
    private TextArea status;
    @FXML
    private ProgressBar progressBar;

    private File input;
    private File output;
    private FileCipher task;

    @FXML
    private void initialize() {
        // Handlers for radio buttons
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
        // Set userDir as default
        inputFile.setText(System.getProperty("user.home").replace("\\", "/"));
        outputFile.setText(System.getProperty("user.home").replace("\\", "/"));
        // Write help
        status.appendText("Select files, choose parameters and press run...");
    }

    /**
     * Select input file.
     */
    @FXML
    private void handleSelectInput() {
        File f = input != null ? selectFile(true, "Select input", input.getParent()) :
                selectFile(true, "Select input");
        if (f != null) {
            input = f;
            inputFile.setText(input.toString().replace("\\", "/"));
        }
    }

    /**
     * Select output file.
     */
    @FXML
    private void handleSelectOutput() {
        File f = input != null ? selectFile(false, "Select output", input.getParent()) :
                selectFile(false, "Select output");
        if (f != null) {
            output = f;
            outputFile.setText(output.toString().replace("\\", "/"));
        }
    }

    /**
     * Run cipher.
     */
    @SuppressWarnings("ThrowableResultOfMethodCallIgnored")
    @FXML
    private void handleRun() {
        // If Cancel button is pressed (while task is running)
        if(handleCancelTask()){
            blockUI(false);
            return;
        }
        // Initial checks
        if (input == null || !input.isFile() || output == null) {
            showError("no-file");
            return;
        } else if (key.getText().equals("")) {
            showError("no-key");
            return;
        }
        // Start process
        blockUI(true);
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
        resetStatus();
        // Create task
        task = new FileCipher(input.getPath(), output.getPath(), key.getText(), encrypt, mode);
        task.getStatus().addListener((observable, oldValue, newValue) -> {
            Platform.runLater(() -> println(newValue)); // Print messages in status box
        });
        task.setOnSucceeded(event -> blockUI(false));
        task.setOnFailed(event -> {
            println("Error: " + task.getException().getMessage());
            blockUI(false);
        });
        progressBar.progressProperty().bind(task.progressProperty());
        // Run task
        new Thread(task).start();
    }

    /**
     * Closes the application.
     */
    @FXML
    private void handleClose() {
        handleCancelTask();
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

    /**
     * Print message in status box.
     */
    private void println(String msg) {
        status.appendText("\n" + msg);
    }

    /**
     * Clear the status box.
     */
    private void resetStatus() {
        status.clear();
        status.appendText("Let's go!");
    }

    /**
     * Disable or enable the interface controls.
     *
     * @param running true: disable / false: enable
     */
    private void blockUI(boolean running) {
        // Change text of Run button
        if(running) {
            run.setText("Cancel");
            runMenu.setText("Cancel");
        } else {
            run.setText("Run");
            runMenu.setText("Run");
        }
        // Disable / enable radio buttons
        selInput.setDisable(running);
        selOutput.setDisable(running);
        // Disable / enable radio buttons
        ToggleGroup[] groups = {operation, operationMenu, operationMode, operationModeMenu};
        for(ToggleGroup g : groups){
            for (Toggle t : g.getToggles()) {
                if(t instanceof RadioButton){
                    ((RadioButton) t).setDisable(running);
                } else {
                    ((RadioMenuItem) t).setDisable(running);
                }
            }
        }
        // Disable / enable key input
        key.setDisable(running);
    }

    /**
     * Cancel task.
     *
     * @return true if the cancel was successful
     */
    private boolean handleCancelTask() {
        boolean canceled = false;
        if(task != null && task.getState() == Worker.State.RUNNING) {
            println("The operation was cancelled!");
            canceled = task.cancel();
        }
        return canceled;
    }

    /**
     * Sync RadioButton and RadioMenuItem.
     *
     * @param group group with the newest state
     * @param groupToUpdate group to update
     */
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

    /**
     * Open a FileChooser to select a file.
     *
     * @param open true: open file / false: save file
     * @param title title of the FileChooser
     * @param path path to open
     * @return selected file
     */
    private File selectFile(boolean open, String title, String path) {
        Stage primaryStage = (Stage) inputFile.getScene().getWindow();
        FileChooser fileChooser = new FileChooser();
        fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("All files (*.*)", "*.*"));
        fileChooser.setInitialDirectory(new File(path));
        fileChooser.setTitle(title);
        return open ? fileChooser.showOpenDialog(primaryStage) : fileChooser.showSaveDialog(primaryStage);
    }

    /**
     * Open a FileChooser to select a file in the default path (user.home).
     */
    private File selectFile(boolean open, String title) {
        return selectFile(open, title, System.getProperty("user.home"));
    }

    /**
     * Open an alert box to show the error.
     */
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