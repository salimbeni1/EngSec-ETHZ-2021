/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package ch.ethz.inf.eventplatformag;

import com.meaningfulmodels.actiongui.jasfag.Window;
import com.meaningfulmodels.actiongui.vm.core.AGSession;
import com.meaningfulmodels.actiongui.vm.vaadinviewer.AppImpl;
import com.meaningfulmodels.actiongui.vm.core.Application;
import com.meaningfulmodels.actiongui.vm.core.IsRoleAnnotation;
import com.meaningfulmodels.actiongui.vm.core.IsUserAnnotation;
import com.meaningfulmodels.actiongui.vm.vaadinviewer.AGServlet;
import com.meaningfulmodels.actiongui.vm.vaadinviewer.ViewerUI;
import com.vaadin.annotations.VaadinServletConfiguration;
import com.vaadin.server.WrappedSession;
import java.io.InputStream;
import java.util.Locale;
import java.util.Map;
import java.util.ResourceBundle;
import javax.servlet.annotation.WebServlet;
import org.modelinglab.ocl.core.ast.expressions.OclExpression;
import org.modelinglab.utils.serialize.core.Serializer;
import org.modelinglab.utils.serialize.java.JavaSerializer;

/**
 *
 */
@WebServlet(value = {"/*"}, name = "AG-Servlet")
@VaadinServletConfiguration(
        productionMode = true,
        ui = ViewerUI.class)
public class MyAGServlet extends AGServlet {

    private static final String RESOURCES_FOLDER = "/";

    @Override
    protected Application createApplication() {
        return new AppImpl(new MyResourceProvider());
    }

    private static class MyResourceProvider extends AppImpl.ResourceProvider {

        private final OclExpression initCallerExp;
        private final OclExpression initRoleExp;
        private final OclExpression initWindowExp;

        private MyResourceProvider() {
            Serializer serializer = new JavaSerializer();
            Map<Class, OclExpression> initExpMap = serializer.load(
                    getClass().getResource(RESOURCES_FOLDER + "initial_expressions.bin"),
                    Map.class);

            initCallerExp = initExpMap.get(IsUserAnnotation.class);
            initRoleExp = initExpMap.get(IsRoleAnnotation.class);
            initWindowExp = initExpMap.get(Window.class);
        }

        @Override
        protected InputStream getPropertiesStream() {
            return getClass().getResourceAsStream(RESOURCES_FOLDER + "appConfig.properties");
        }

        @Override
        protected InputStream getJasfagStream() {
            return getClass().getResourceAsStream(RESOURCES_FOLDER + "jasfag.xml");
        }

        @Override
        protected InputStream getSdamStream() {
            return getClass().getResourceAsStream(RESOURCES_FOLDER + "sdam.xml");
        }

        @Override
        protected InputStream getEntitiesStream() {
            return getClass().getResourceAsStream(RESOURCES_FOLDER + "umlclasses.xml");
        }

        @Override
        protected ResourceBundle getResourceBundle(Locale userLocale) {
            return ResourceBundle.getBundle(RESOURCES_FOLDER + "localitation/localitation", userLocale);
        }

        @Override
        protected AGSession createSession(WrappedSession session) {
            return new MyAGSession();
        }

        @Override
        protected OclExpression getInitialCallerExpression() {
            return initCallerExp;
        }

        @Override
        protected OclExpression getInitialRoleExpression() {
            return initRoleExp;
        }

        @Override
        protected OclExpression getInitialWindowExpression() {
            return initWindowExp;
        }
    }

}
