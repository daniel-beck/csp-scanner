package io.jenkins.security.csp;

import java.io.File;
import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

public class Scanner {
    private static final String JS_EVENT_ATTRIBUTES = "(on(auxclick|beforeinput|beforematch|beforetoggle|blur|cancel|canplay|canplaythrough|change|click|close|contextlost|contextmenu|contextrestored|copy|cuechange|cut|dblclick|drag|dragend|dragenter|dragleave|dragover|dragstart|drop|durationchange|emptied|ended|error|focus|formdata|input|invalid|keydown|keypress|keyup|load|loadeddata|loadedmetadata|loadstart|mousedown|mouseenter|mouseleave|mousemove|mouseout|mouseover|mouseup|paste|pause|play|playing|progress|ratechange|reset|resize|scroll|scrollend|securitypolicyviolation|seeked|seeking|select|slotchange|stalled|submit|suspend|timeupdate|toggle|volumechange|waiting|wheel))";

    /**
     * Patterns identified in .jelly files
     */
    protected static final Map<String, Pattern> JELLY_PATTERNS = Map.of("Inline Event Handler", Pattern.compile("<[^>]+\\s" + JS_EVENT_ATTRIBUTES + "=[^>]+>", Pattern.CASE_INSENSITIVE),
            "Inline Script Block", Pattern.compile("(<script>|<script[^>]*[^/]>)\\s*?(?!</script>)\\S.*?</script>", Pattern.DOTALL | Pattern.CASE_INSENSITIVE),
            "Legacy checkUrl", Pattern.compile("(checkUrl=\"[^\"]*'[^\"]*'[^\"]*\")|(checkUrl='[^']*\"[^']*\"[^']*')", Pattern.CASE_INSENSITIVE));

    /**
     * Patterns identified in .js files
     */
    // Examples indicate trying to match open-paren would be too restrictive:
    // https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval#direct_and_indirect_eval
    // geval is defined in hudson-behavior.js
    protected static final Map<String, Pattern> JS_PATTERNS = Map.of("(g)eval Call", Pattern.compile("\\Wg?eval\\W"));

    protected static final Map<String, Pattern> JAVA_PATTERNS = Map.of("Inline Event Handler (Java)", Pattern.compile("(?<![a-z0-9])" + JS_EVENT_ATTRIBUTES + "=.*?((?<!\\\\)\")", Pattern.CASE_INSENSITIVE),
            "Inline Script Block (Java)", Pattern.compile("(<script>|<script[^>]*[^/]>)\\s*?(?!</script>)\\S.*?</script>", Pattern.DOTALL | Pattern.CASE_INSENSITIVE));

    protected static class Match {
        protected final String title;
        protected final String match;
        protected final File file;

        private Match(String title, String match, File file) {
            this.title = title;
            this.match = match;
            this.file = file;
        }
    }

    public static void main(String[] args) {
        if (args.length < 1) {
            System.err.println("Usage: java -jar csp-scanner.jar <file-or-dir> [<file-or-dir> ...]");
            System.exit(1);
        }

        Arrays.stream(args).forEach(arg -> {
            File file = new File(arg);

            if (!file.exists()) {
                System.err.println("File or directory does not exist: " + file);
                return;
            }

            if (file.isFile()) {
                try {
                    visitFile(file);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
                return;
            }

            if (file.isDirectory()) {
                try {
                    Files.walkFileTree(file.toPath(), new TheFileVisitor());
                } catch (IOException e) {
                    System.err.println("Failed to visit directory '" + file + "':");
                    e.printStackTrace(System.err);
                }
                return;
            }

            System.err.println("Not a file or directory: " + file);
        });
    }

    private static void visitFile(File file) throws IOException {
        final String fileName = file.getName();
        if (fileName.endsWith(".jelly") || fileName.endsWith(".html") || fileName.endsWith(".properties")) {
            final String text = Files.readString(file.toPath());
            printMatches(matchRegexes(JELLY_PATTERNS, text, file));
        }

        if (fileName.endsWith(".java")) {
            final String text = Files.readString(file.toPath());
            printMatches(matchRegexes(JAVA_PATTERNS, text, file));
        }

        if (fileName.endsWith(".js")) {
            final String text = Files.readString(file.toPath());
            printMatches(matchRegexes(JS_PATTERNS, text, file));
        }
    }

    private static void printMatches(List<Match> matches) {
        matches.forEach(match -> {
            System.out.println("== " + match.title);
            System.out.println("File: " + match.file.toPath());
            System.out.println("----");
            System.out.println(match.match);
            System.out.println("----");
            System.out.println();
        });
    }

    public static List<Match> matchRegexes(Map<String, Pattern> patterns, String text, File file) {
        List<Match> results = new ArrayList<>();
        patterns.forEach((title, pattern) -> {
            pattern.matcher(text).results().forEach(result -> {
                results.add(new Match(title, result.group(), file));
            });
        });
        return results;
    }

    private static class TheFileVisitor extends SimpleFileVisitor<Path> {
        @Override
        public FileVisitResult visitFile(java.nio.file.Path file, BasicFileAttributes attrs) {
            try {
                Scanner.visitFile(file.toFile());
            } catch (Exception e) {
                System.err.println("Failed to visit file '" + file + "':");
                e.printStackTrace(System.err);
            }
            return FileVisitResult.CONTINUE;
        }

        @Override
        public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) throws IOException {
            final Path dirName = dir.getFileName();
            if (Set.of(Path.of("work"), Path.of("target"), Path.of("node_modules")).contains(dirName)) {
                return FileVisitResult.SKIP_SUBTREE;
            }
            return FileVisitResult.CONTINUE;
        }
    }
}
