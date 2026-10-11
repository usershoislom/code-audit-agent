import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class UserServletFixed extends HttpServlet {
    private Connection conn;

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String name = request.getParameter("name");
        try {
            PreparedStatement ps = conn.prepareStatement("SELECT email FROM users WHERE name = ?");
            ps.setString(1, name);
            ResultSet rs = ps.executeQuery();
            response.getWriter().println(rs.next() ? "found" : "none");
        } catch (Exception e) {
            response.sendError(500);
        }
    }
}
