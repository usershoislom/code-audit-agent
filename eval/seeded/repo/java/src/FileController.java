import java.nio.file.Files;
import java.nio.file.Paths;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class FileController {
    @GetMapping("/files")
    public String read(@RequestParam String name) throws Exception {
        return new String(Files.readAllBytes(Paths.get("/srv/files/" + name)));
    }

    @GetMapping("/ping")
    public String ping(@RequestParam("host") String host) throws Exception {
        Process p = Runtime.getRuntime().exec("ping -c 1 " + host);
        return String.valueOf(p.waitFor());
    }
}
