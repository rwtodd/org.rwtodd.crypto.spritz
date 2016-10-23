/*
 * Copyright Richard Todd. I put the code under the
 * GPL v2.0.  See the LICENSE file in the repository.
 * for more information.
 */
package rwt.spritz

import javafx.application.Application
import javafx.fxml.FXMLLoader
import javafx.scene.{Parent,Scene}
import javafx.stage.Stage

/**
 *
 * @author richa
 */
final class EncrNotes extends Application {
    override
    def start(stage : Stage) : Unit =  {
        val root : Parent =
	  FXMLLoader.load(getClass().getResource("/fxml/MainWin.fxml"))
        
        stage.setTitle("EncrNotes Application")
        stage.setScene(new Scene(root))
        stage.show()
    }
}

object Main {
    /**
     * @param args the command line arguments
     */
    def main(args : Array[String]) : Unit = {
        Application.launch(classOf[EncrNotes], args: _*)
    }
    
}
