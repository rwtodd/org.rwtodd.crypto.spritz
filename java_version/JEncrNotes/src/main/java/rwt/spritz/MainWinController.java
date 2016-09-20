/*
 * Copyright Richard Todd. I put the code under the
 * GPL v2.0.  See the LICENSE file in the repository.
 * for more information.
 */
package rwt.spritz;

import java.net.URL;
import java.util.ResourceBundle;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.layout.BorderPane;
import javafx.scene.control.TextArea;
import javafx.scene.layout.HBox;
import javafx.stage.FileChooser;
import java.io.File;
import com.waywardcode.crypto.*;
import java.util.Optional;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.control.TextField;
import javafx.stage.Stage;

/**
 *
 * @author richa
 */
public class MainWinController implements Initializable {

    private File loadedFile; /* what do we have loaded? */
    
    @FXML
    private BorderPane root;
    
    @FXML
    private HBox passwField;
    
    @FXML
    private TextField passw;
    
    @FXML
    private TextArea editor;

    @FXML
    private void menuSave(ActionEvent e) {
        if (passw.getText().length() == 0) return;

        File file = loadedFile;
        if(file == null) {
            FileChooser fileChooser = new FileChooser();
            fileChooser.setTitle("Save Text File");
            file = fileChooser.showSaveDialog(root.getScene().getWindow());
        }
        if(file == null) return;
        
        // if file exists, back it up...
        if(file.exists()) {
            try {
                File toSave = new File(file.getPath() + ".bak");
                java.nio.file.Files.move(file.toPath(), toSave.toPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            } catch(Exception ex) {
                System.err.println(ex);
                return;
            }
        }
        
        // ok, now write out the new text...
        try (
                final java.io.FileOutputStream fos = new java.io.FileOutputStream(file);
                final SpritzOutputStream sos = new SpritzOutputStream(Optional.empty(), passw.getText(), fos);
                final java.io.OutputStreamWriter wtr = new java.io.OutputStreamWriter(sos.getOutputStream(),java.nio.charset.StandardCharsets.UTF_8)
            ) {
            wtr.write(editor.getText());
        } catch(Exception ex) {
            System.err.println(ex);
            return;
        }
        loadedFile = file;
        passw.editableProperty().set(false); // lock it down once it's in use...
        passwField.visibleProperty().set(false);
    }
    
    @FXML
    private void menuOpen(ActionEvent e) {
        if (passw.getText().length() == 0) return;
        
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Open File");
        File file = fileChooser.showOpenDialog(root.getScene().getWindow());
        if(file != null) {
            try(
                final java.io.FileInputStream fin = new java.io.FileInputStream(file);
                final SpritzInputStream sin = new SpritzInputStream(passw.getText(),fin);
                final java.io.InputStreamReader isr = new java.io.InputStreamReader(sin.getInputStream(),java.nio.charset.StandardCharsets.UTF_8);
                final java.io.BufferedReader rdr = new java.io.BufferedReader(isr)
               ) {
                final StringBuilder sb = new StringBuilder();
                String line = rdr.readLine();
                while(line != null) {
                    sb.append(line).append('\n');
                    line = rdr.readLine();
                }
                editor.setText(sb.toString());
                passw.editableProperty().set(false); // lock it down once it's right...
                passwField.visibleProperty().set(false);
                loadedFile = file;
            } catch (Exception ex) {
                editor.setText(ex.toString());
            }
        }
    }
    
    @FXML
    private void menuEditPW(ActionEvent e) {
        passwField.visibleProperty().set(true);
        passw.editableProperty().set(true);
    }
    
    @FXML
    private void menuRender(ActionEvent e) {
        try {
            FXMLLoader loader = new FXMLLoader(
                    getClass().getResource("RenderedWin.fxml")
            );
            Scene myScene = root.getScene();
            Scene renderScene = new Scene(loader.load());
            RenderedWinController rwc = loader.getController();
            rwc.setData(myScene, editor.getText());
            ((Stage) editor.getScene().getWindow()).setScene(renderScene);
        } catch (Exception except) {
            // guess it didn't work :(
        }
    }
    
    @FXML
    private void menuExit(ActionEvent e) {
        System.exit(0);
    }
    
    @Override
    public void initialize(URL url, ResourceBundle rb) {
        editor.setText("*hi* there");
        // remove the password field from the layout when I make it invisible
        passwField.managedProperty().bind(passwField.visibleProperty());
    }    
    
}
