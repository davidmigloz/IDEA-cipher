package com.davidmiguel.idea_cifer;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

/**
 * Starts IDEA cipher GUI.
 */
public class MainApp extends Application{
    @Override
    public void start(Stage primaryStage) throws Exception {
        final Parent root = FXMLLoader.load(getClass().getResource("/fxml/gui.fxml"));
        final Scene scene = new Scene(root);
        primaryStage.setTitle("IDEA cipher");
        primaryStage.setResizable(false);
        primaryStage.setScene(scene);
        primaryStage.sizeToScene();
        primaryStage.centerOnScreen();
        primaryStage.show();
    }

    public static void main(String[] args) {
        launch(args);
    }
}
