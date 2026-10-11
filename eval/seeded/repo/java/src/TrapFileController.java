import java.nio.file.Files;
import java.nio.file.Paths;
import org.apache.commons.io.FilenameUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TrapFileController {
    @GetMapping("/files")
    public String read(@RequestParam String name) throws Exception {
        String safe = FilenameUtils.getName(name);
        return new String(Files.readAllBytes(Paths.get("/srv/files/", safe)));
    }

    @GetMapping("/page")
    public String page(@RequestParam("n") String n) throws Exception {
        int page = Integer.parseInt(n);
        Process p = Runtime.getRuntime().exec(new String[]{"report", String.valueOf(page)});
        return String.valueOf(p.waitFor());
    }
}
