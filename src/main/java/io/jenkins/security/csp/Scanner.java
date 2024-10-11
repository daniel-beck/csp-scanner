package io.jenkins.security.csp;

import java.io.File;
import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Arrays;
import java.util.Map;
import java.util.regex.Pattern;

public class Scanner {
    /**
     * Patterns identified in .jelly files
     */
    private static final Map<String, Pattern> JELLY_PATTERNS = Map.of("Inline Event Handler", Pattern.compile("<[^>]+\\s(on[a-z]+)=[^>]+>"),
            "Inline Script Block", Pattern.compile("<script.*>.*\\S+.*</script>"),
            "Legacy checkUrl", Pattern.compile("(checkUrl=\"[^\"]*'[^\"]*'\")|(checkUrl='[^']*\"[^']*\"')"));

    /**
     * Patterns identified in .js files
     */
    // Examples indicate trying to match open-paren would be too restrictive:
    // https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval#direct_and_indirect_eval
    // geval is defined in hudson-behavior.js
    private static final Map<String, Pattern> JS_PATTERNS = Map.of("(g)eval Call", Pattern.compile("\\Wg?eval\\W"));

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
                    System.err.println("Failed to visit directory: " + file);
                }
                return;
            }

            System.err.println("Not a file or directory: " + file);
        });
    }

    private static void visitFile(File file) throws IOException {
        if (file.getName().endsWith(".jelly")) {
            final String text = Files.readString(file.toPath());
            JELLY_PATTERNS.forEach((title, pattern) -> matchRegex(file, text, title, pattern));
        }

        if (file.getName().endsWith(".js")) {
            final String text = Files.readString(file.toPath());
            JS_PATTERNS.forEach((title, pattern) -> matchRegex(file, text, title, pattern));
        }
    }

    private static void matchRegex(File file, String text, String patternTitle, Pattern pattern) {
        pattern.matcher(text).results().forEach(matchResult -> {
            System.out.println("== " + patternTitle);
            System.out.println("File: " + file.toPath());
            System.out.println("----");
            System.out.println(matchResult.group());
            System.out.println("----");
            System.out.println();
        });
    }

    private static class TheFileVisitor extends SimpleFileVisitor<Path> {
        @Override
        public FileVisitResult visitFile(java.nio.file.Path file, BasicFileAttributes attrs) throws IOException {
            Scanner.visitFile(file.toFile());
            return FileVisitResult.CONTINUE;
        }
    }
}
