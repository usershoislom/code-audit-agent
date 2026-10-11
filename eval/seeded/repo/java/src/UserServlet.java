import java.io.IOException;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class UserServlet extends HttpServlet {
    private Connection conn;

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String name = request.getParameter("name");
        try {
            Statement st = conn.createStatement();
            ResultSet rs = st.executeQuery("SELECT email FROM users WHERE name = '" + name + "'");
            response.getWriter().println(rs.next() ? "found" : "none");
        } catch (Exception e) {
            response.sendError(500);
        }
    }
}
