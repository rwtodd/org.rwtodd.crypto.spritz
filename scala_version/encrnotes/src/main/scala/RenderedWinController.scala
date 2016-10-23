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
import javafx.scene.Scene
import javafx.stage.Stage

import org.commonmark.html.HtmlRenderer
import org.commonmark.parser.Parser

/**
 * FXML Controller class
 *
 * @author rtodd
 */
class RenderedWinController {

    @FXML private var webview : javafx.scene.web.WebView = null
    private var parentScene : Scene = null
    
    @FXML private def exitPressed(e : ActionEvent) : Unit = {
         webview.getScene()
	        .getWindow()
		.asInstanceOf[Stage]
		.setScene(parentScene)
    }
    
    /**
     * Initializes the controller class.
     */
    def initialize() : Unit = {
        webview.getEngine().loadContent("<p>Loading...</p>")
    }
    
    def setData(parent: Scene, markdown: String) : Unit = {
        parentScene = parent
        
        // this really should be fast enough that I don't need to make it
        // asynchronous.... the notes aren't going to be that big.
        val parser = Parser.builder().build()
        val renderer = HtmlRenderer.builder().build()
        val html = renderer.render(parser.parse(markdown))
       
        webview.getEngine().loadContent(html)
    }
    
}
