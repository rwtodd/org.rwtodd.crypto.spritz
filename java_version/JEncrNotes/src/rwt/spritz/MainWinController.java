/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package rwt.spritz;

import java.net.URL;
import java.util.ResourceBundle;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.layout.VBox;
import javafx.scene.web.HTMLEditor;
import javafx.stage.FileChooser;
import java.io.File;
import com.waywardcode.crypto.*;
import java.util.Optional;
import javafx.scene.control.TextField;

/**
 *
 * @author richa
 */
public class MainWinController implements Initializable {

    private File loadedFile; /* what do we have loaded? */
    
    @FXML
    private VBox root;
    
    @FXML
    private TextField passw;
    
    @FXML
    private HTMLEditor editor;

    @FXML
    private void menuSave(ActionEvent e) {
        if (passw.getText().length() == 0) return;

        File file = loadedFile;
        if(file == null) {
            FileChooser fileChooser = new FileChooser();
            fileChooser.setTitle("Save HTML File");
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
                final java.io.OutputStreamWriter wtr = new java.io.OutputStreamWriter(sos,java.nio.charset.StandardCharsets.UTF_8)
            ) {
            wtr.write(editor.getHtmlText());
        } catch(Exception ex) {
            System.err.println(ex);
            return;
        }
        loadedFile = file;
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
                final java.io.InputStreamReader isr = new java.io.InputStreamReader(sin,java.nio.charset.StandardCharsets.UTF_8);
                final java.io.BufferedReader rdr = new java.io.BufferedReader(isr)
               ) {
                final StringBuffer sb = new StringBuffer();
                String line = rdr.readLine();
                while(line != null) {
                    sb.append(line);
                    line = rdr.readLine();
                }
                editor.setHtmlText(sb.toString());
                loadedFile = file;
            } catch (Exception ex) {
                System.err.println(ex);
            }
        }
    }
    
    @FXML
    private void menuExit(ActionEvent e) {
        System.exit(0);
    }
    
    @Override
    public void initialize(URL url, ResourceBundle rb) {
        editor.setHtmlText("<b>hi</b> there");
    }    
    
}
