package io.jenkins.security.csp;

import java.io.File;
import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Arrays;
import java.util.regex.Pattern;

public class Locator {
    public static void main(String[] args) throws IOException {

        if (args.length < 1) {
            System.err.println("Usage: java -jar csp-regex.jar <file-or-dir> [<file-or-dir> ...]");
            System.exit(1);
        }

        Arrays.stream(args).forEach(arg -> {
            File file = new File(arg);

            if (!file.exists()) {
                System.err.println("File or directory does not exist: " + file);
                return;
            }

            if (file.isFile()) {
                visitFile(file);
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

    private static void visitFile(File file) {
        if (file.getName().endsWith(".jelly")) {
            var eventHandlerRegex = "<[^>]+\\s(on[a-z]+)=[^>]+>";
            var scriptRegex = "<script.*>.*\\S+.*</script>";
            var checkUrlRegex = "(checkUrl=\"[^\"]*'[^\"]*'\")|(checkUrl='[^']*\"[^']*\"')";

            var anyRegex = "(" + eventHandlerRegex + ")|(" + scriptRegex + ")|(" + checkUrlRegex + ")";

            matchRegex(file, anyRegex);
        }

        if (file.getName().endsWith(".js")) {
            matchRegex(file, "\\seval[(`]");
        }
    }

    private static void matchRegex(File file, String regex) {
        try {
            final String text = Files.readString(file.toPath());
            final Pattern pattern = Pattern.compile(regex);

            pattern.matcher(text).results().forEach(matchResult -> {
                System.out.println("== Match in " + file);
                System.out.println("----");
                System.out.println(matchResult.group());
                System.out.println("----");
                System.out.println();
            });

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static class TheFileVisitor extends SimpleFileVisitor<Path> {
        @Override
        public FileVisitResult visitFile(java.nio.file.Path file, BasicFileAttributes attrs) throws IOException {
            Locator.visitFile(file.toFile());
            return FileVisitResult.CONTINUE;
        }
    }
}
