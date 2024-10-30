package io.jenkins.security.csp;

import java.io.File;
import java.io.IOException;
import java.nio.charset.MalformedInputException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class Scanner {
    private static final String JS_EVENT_ATTRIBUTES = "(on(abort|afterprint|animationcancel|animationend|animationiteration|animationstart|appinstalled|auxclick|beforeinput|beforeinstallprompt|beforematch|beforeprint|beforetoggle|beforeunload|blur|cancel|canplay|canplaythrough|change|click|close|compositionend|compositionstart|compositionupdate|contentvisibilityautostatechange|contextmenu|copy|cuechange|cut|dblclick|devicemotion|deviceorientation|deviceorientationabsolute|DOMContentLoaded|drag|dragend|dragenter|dragleave|dragover|dragstart|drop|durationchange|emptied|encrypted|ended|endEvent|error|focus|focusin|focusout|formdata|fullscreenchange|fullscreenerror|gamepadconnected|gamepaddisconnected|gotpointercapture|hashchange|input|invalid|keydown|keypress|keyup|languagechange|load|loadeddata|loadedmetadata|loadend|loadstart|lostpointercapture|message|messageerror|mousedown|mouseenter|mouseleave|mousemove|mouseout|mouseover|mouseup|mousewheel|offline|online|pagehide|pageshow|paste|pause|play|playing|pointercancel|pointerdown|pointerenter|pointerleave|pointerlockchange|pointerlockerror|pointermove|pointerout|pointerover|pointerup|popstate|progress|ratechange|readystatechange|rejectionhandled|resize|resourcetimingbufferfull|resume|scroll|scrollend|securitypolicyviolation|seeked|seeking|select|selectionchange|slotchange|stalled|start|stop|storage|submit|suspend|timeupdate|timeout|toggle|touchcancel|touchend|touchmove|touchstart|transitioncancel|transitionend|transitionrun|transitionstart|unhandledrejection|visibilitychange|volumechange|waiting|wheel))";

    /**
     * Patterns identified in .jelly files
     */
    protected static final Map<String, Pattern> JELLY_PATTERNS = Map.of("Inline Event Handler", Pattern.compile("<[^>]+\\s" + JS_EVENT_ATTRIBUTES + "=[^>]+>", Pattern.CASE_INSENSITIVE),
            "Inline Script Block", Pattern.compile("(<script>|<script(|\\s[^>]*)[^/]>)\\s*?(?!</script>)\\S.*?</script>", Pattern.DOTALL | Pattern.CASE_INSENSITIVE),
            "Legacy checkUrl", Pattern.compile("(checkUrl=\"[^\"]*'[^\"]*'[^\"]*\")|(checkUrl='[^']*\"[^']*\"[^']*')", Pattern.CASE_INSENSITIVE),
            "Javascript scheme", Pattern.compile("<[^>]+javascript:[^>]+>", Pattern.CASE_INSENSITIVE));

    /**
     * Patterns identified in .js files
     */
    // Examples indicate trying to match open-paren would be too restrictive:
    // https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval#direct_and_indirect_eval
    // geval is defined in hudson-behavior.js
    protected static final Map<String, Pattern> JS_PATTERNS = Map.of("(g)eval Call", Pattern.compile("\\Wg?eval\\W"));

    protected static final Map<String, Pattern> JAVA_PATTERNS = Map.of("Inline Event Handler (Java)", Pattern.compile("(?<![a-z0-9])" + JS_EVENT_ATTRIBUTES + "=.*?((?<!\\\\)\")", Pattern.CASE_INSENSITIVE),
            "Inline Script Block (Java)", Pattern.compile("(<script>|<script(|\\s[^>]*)[^/]>)\\s*?(?!</script>)\\S.*?</script>", Pattern.DOTALL | Pattern.CASE_INSENSITIVE),
            "FormApply#applyResponse", Pattern.compile("FormApply[.]applyResponse[(].*"),
            "Javascript scheme (Java)", Pattern.compile("\".*(?<![a-z0-9])javascript:.*?((?<!\\\\)\")", Pattern.CASE_INSENSITIVE));

    protected static class Match {
        protected final String title;
        protected final String match;
        protected final File file;
        private final long line;

        private Match(String title, String match, File file, long line) {
            this.title = title;
            this.match = match;
            this.file = file;
            this.line = line;
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
                final HashSet<Match> matches = new HashSet<>();
                try {
                    visitFile(file, matches);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
                printMatches(matches.stream().sorted(Comparator.comparing(u -> u.title + u.file + u.line)).collect(Collectors.toList()));
                return;
            }

            if (file.isDirectory()) {
                final TheFileVisitor visitor = new TheFileVisitor();
                try {
                    Files.walkFileTree(file.toPath(), visitor);
                } catch (IOException e) {
                    System.err.println("Failed to visit directory '" + file + "':");
                    e.printStackTrace(System.err);
                }
                printMatches(visitor.matches.stream().sorted(Comparator.comparing(u -> u.title + u.file + u.line)).collect(Collectors.toList()));
                return;
            }

            System.err.println("Not a file or directory: " + file);
        });
    }

    private static String readFileToString(File file) throws IOException {
        try {
            return Files.readString(file.toPath());
        } catch (MalformedInputException ex) {
            // re-try with Latin-1 per https://github.com/daniel-beck/csp-scanner/pull/10#issuecomment-2423384611
            // Technically only applies to .properties, and this is used for all files, but likely to be correct enough.
            return Files.readString(file.toPath(), StandardCharsets.ISO_8859_1);
        }
    }

    private static void visitFile(File file, Set<Match> matches) throws IOException {
        final String fileName = file.getName();
        if (fileName.startsWith("update-center.json")) {
            return;
        }
        if (fileName.startsWith("yui-license.html")) {
            return;
        }
        if (fileName.endsWith(".jelly") || fileName.endsWith(".html") || fileName.endsWith(".properties")) {
            final String text = readFileToString(file);
            matches.addAll(matchRegexes(JELLY_PATTERNS, text, file));
        }

        if (fileName.endsWith(".java")) {
            final String text = readFileToString(file);
            printMatches(matchRegexes(JAVA_PATTERNS, text, file));
        }

        if (fileName.endsWith(".js")) {
            final String text = readFileToString(file);
            matches.addAll(matchRegexes(JS_PATTERNS, text, file));
        }
    }

    private static void printMatches(List<Match> matches) {
        matches.forEach(match -> {
            System.out.println("== " + match.title);
            System.out.println("File: " + match.file.toPath() + " +");
            System.out.println("Line: " + match.line);
            System.out.println("----");
            System.out.println(match.match);
            System.out.println("----");
            System.out.println();
        });
    }

    private static Pattern LINE_BREAK = Pattern.compile("\\R");

    public static List<Match> matchRegexes(Map<String, Pattern> patterns, String text, File file) {
        List<Match> results = new ArrayList<>();
        patterns.forEach((title, pattern) -> {
            pattern.matcher(text).results().forEach(result -> {
                final long line = LINE_BREAK.matcher(text.substring(0, result.start())).results().count() + 1;
                results.add(new Match(title, result.group(), file, line));
            });
        });
        return results;
    }

    private static class TheFileVisitor extends SimpleFileVisitor<Path> {
        private final Set<Match> matches = new HashSet<>();
        @Override
        public FileVisitResult visitFile(java.nio.file.Path file, BasicFileAttributes attrs) {
            try {
                Scanner.visitFile(file.toFile(), matches);
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
