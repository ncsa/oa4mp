package edu.uiuc.ncsa.oa4mp;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

import java.net.URL;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/24/19 at  4:09 PM
 */
public class ScriptGUI extends Application {
    public static void main(String[] args) {
          System.out.println("ScriptGUI");
          launch(args);
      }

      @Override
      public void start(Stage primaryStage) throws Exception{
          URL url2 = new URL("file:///home/ncsa/dev/ncsa-git/oa4mp/oa4mp-gui/src/main/java/edu/uiuc/ncsa/oa4mp/edit_script.fxml");
          Parent root = FXMLLoader.load(url2);
          primaryStage.setTitle("Script Editor");
          primaryStage.setScene(new Scene(root, 1024, 768));
          primaryStage.show();
      }

}
