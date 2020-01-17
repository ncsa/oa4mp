package edu.uiuc.ncsa.oa4mp;/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/19/19 at  1:33 PM
 */

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

import java.net.URL;

public class OA2GUI extends Application {

    public static void main(String[] args) {
        System.out.println("Yo2!");
        launch(args);
    }

    @Override
    public void start(Stage primaryStage) throws Exception{
        URL url2 = new URL("file:///home/ncsa/dev/ncsa-git/oa4mp/oa4mp-gui/src/main/java/edu/uiuc/ncsa/oa4mp/gui2.fxml");
        Parent root = FXMLLoader.load(url2);
        primaryStage.setTitle("OA4MP Client Configuration Notebook");
        primaryStage.setScene(new Scene(root, 1024, 768));
        primaryStage.show();
    }

}
