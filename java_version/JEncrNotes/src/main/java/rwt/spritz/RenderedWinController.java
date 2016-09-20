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
import javafx.scene.Scene;
import javafx.stage.Stage;

import org.commonmark.html.HtmlRenderer;
import org.commonmark.parser.Parser;

/**
 * FXML Controller class
 *
 * @author rtodd
 */
public class RenderedWinController implements Initializable {

    @FXML private javafx.scene.web.WebView webview;
    
    @FXML private void exitPressed(ActionEvent e) {
          ((Stage)webview.getScene().getWindow()).setScene(parentScene);
    }
    
    /**
     * Initializes the controller class.
     */
    @Override
    public void initialize(URL url, ResourceBundle rb) {
        webview.getEngine().loadContent("<p>Loading...</p>");
    }    

    private Scene parentScene;
    
    public void setData(javafx.scene.Scene parent, String markdown) {
        parentScene = parent;
        
        // this really should be fast enough that I don't need to make it
        // asynchronous.... the notes aren't going to be that big.
        Parser parser = Parser.builder().build();
        HtmlRenderer renderer = HtmlRenderer.builder().build();
        String html = renderer.render(parser.parse(markdown));
       
        webview.getEngine().loadContent(html);
        
    }
    
}
