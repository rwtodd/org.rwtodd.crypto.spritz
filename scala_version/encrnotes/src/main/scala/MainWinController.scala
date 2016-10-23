/*
 * Copyright Richard Todd. I put the code under the
 * GPL v2.0.  See the LICENSE file in the repository.
 * for more information.
 */
package rwt.spritz

import java.net.URL
import java.util.ResourceBundle
import javafx.event.ActionEvent
import javafx.fxml.FXML
import javafx.fxml.Initializable
import javafx.scene.layout.BorderPane
import javafx.scene.control.TextArea
import javafx.scene.layout.HBox
import javafx.stage.FileChooser
import java.io.File
import com.waywardcode.crypto._
import java.util.Optional
import javafx.fxml.FXMLLoader
import javafx.scene.Scene
import javafx.scene.control.TextField
import javafx.stage.Stage
import java.nio.charset.StandardCharsets.UTF_8	

/**
 *
 * @author richa
 */
class MainWinController {

    private var loadedFile : File = null  /* what do we have loaded? */
    
    @FXML private var root : BorderPane = null    
    @FXML private var passwField : HBox = null    
    @FXML private var passw : TextField = null
    @FXML private var editor : TextArea = null

    @FXML
    private def menuSave(e: ActionEvent) : Unit = {
        if (passw.getText().length() == 0) return

        var file = loadedFile
        if(file == null) {
            val fileChooser = new FileChooser()
            fileChooser.setTitle("Save Text File")
            file = fileChooser.showSaveDialog(root.getScene().getWindow())
        }
        if(file == null) return
        
        // if file exists, back it up...
        if(file.exists()) {
            try {
                val toSave = new File(file.getPath() + ".bak")
                java.nio.file.Files.move(file.toPath(),
		                         toSave.toPath(),
					 java.nio.file.StandardCopyOption.REPLACE_EXISTING)
            } catch {
	      case ex : Exception => {
                System.err.println(ex)
                return
	      }
            }
        }
        
        // ok, now write out the new text...
        val fos = new java.io.FileOutputStream(file)
        val sos = new SpritzOutputStream(None, passw.getText(), fos)
        val wtr = new java.io.OutputStreamWriter(sos.outputStream, UTF_8)
           
        try {
            wtr.write(editor.getText())
        } catch {
	  case ex : Exception => {
            System.err.println(ex)
            return
	  }
        } finally {
	   wtr.close()
           sos.close()
           fos.close()
        }
        loadedFile = file
	
	// lock down password once it's in use...
        passw.editableProperty().set(false)
        passwField.visibleProperty().set(false)
    }
    
    @FXML
    private def menuOpen(e: ActionEvent) : Unit = {
        if (passw.getText().length() == 0) return
        
        val fileChooser = new FileChooser()
        fileChooser.setTitle("Open File")
        val file = fileChooser.showOpenDialog(root.getScene().getWindow())
        if(file != null) {
            val fin = new java.io.FileInputStream(file)
            val sin = new SpritzInputStream(passw.getText(),fin)
            val isr = new java.io.InputStreamReader(sin.inputStream, UTF_8)
            val rdr = new java.io.BufferedReader(isr)
            try {
                val sb = new StringBuilder()
                var line = rdr.readLine()
                while(line != null) {
                    sb.append(line).append('\n')
                    line = rdr.readLine()
                }
                editor.setText(sb.toString())

                // lock password down once it's right...
                passw.editableProperty().set(false);		
                passwField.visibleProperty().set(false)
                loadedFile = file
            } catch {
	       case ex : Exception =>  {
                editor.setText(ex.toString())
	       }
            } finally {
               rdr.close()
	       isr.close()
	       sin.close()
	       fin.close()
            }
        }
    }
    
    @FXML
    private def menuEditPW(e: ActionEvent) : Unit = {
        passwField.visibleProperty().set(true)
        passw.editableProperty().set(true)
    }
    
    @FXML
    private def menuRender(e : ActionEvent) : Unit = {
        try {
            val loader = new FXMLLoader(
                    getClass().getResource("/fxml/RenderedWin.fxml")
            )
            val myScene = root.getScene()
            val renderScene = new Scene(loader.load())
            val rwc : RenderedWinController = loader.getController()
            rwc.setData(myScene, editor.getText())
            editor.getScene()
	          .getWindow()
		  .asInstanceOf[Stage]
		  .setScene(renderScene)
        } catch {
	   case except : Exception  => { 
               // guess it didn't work :(
	   }
        }
    }
    
    @FXML
    private def menuExit(e : ActionEvent) : Unit = {
        System.exit(0)
    }

    def initialize() : Unit = {
        editor.setText("*hi* there")
	
        // remove the password field from the layout when I make it invisible
        passwField.managedProperty()
	          .bind(passwField.visibleProperty())
    }    
    
}
