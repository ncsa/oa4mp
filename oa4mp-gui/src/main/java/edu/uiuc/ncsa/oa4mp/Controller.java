package edu.uiuc.ncsa.oa4mp;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/19/19 at  5:30 PM
 */
import javafx.event.ActionEvent;
import javafx.scene.control.*;

public class Controller {

    public TextField field_name;
    public TextField field_email;
    public TextField field_home_uri;
    public TextField field_id;
    public TextField field_secret;
    public RadioButton button_is_public;
    public TextField field_refresh_lifetime;
    public TextArea field_redirect;
    public CheckBox cb_isPublic;
    public CheckBox cb_open_id;
    public CheckBox cb_email;
    public CheckBox cb_profile;
    public CheckBox cb_user_info;
    public CheckBox cb_get_cert;
    public TextArea text_comments;
    public TextField test_claim_source_name_1;
    public TextField test_claim_source_id_1;
    public TextArea ta_global_preProcessor;
    public TextArea ta_global_postProcessor;
    public TableView table_claim_sources;

    public void editRuntime(ActionEvent actionEvent) {
        System.out.println("Yo!");

    }

    public void populate(ActionEvent actionEvent) {
    }

    public void load(ActionEvent actionEvent) {
        Injector injector = new Injector(this);
        try {
            injector.readRecord("/home/ncsa/temp/client.xml");
            injector.inject();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
