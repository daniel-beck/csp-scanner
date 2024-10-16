package io.jenkins.security.csp;

import java.io.File;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.hamcrest.CoreMatchers;
import org.hamcrest.Matcher;
import org.hamcrest.Matchers;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;

public class ScannerTest {
    @Test
    public void issue2() {
        assertMatch("<f:textbox name=\"aggregatedTestResult.jobs\" value=\"${instance.jobs}\"\n" +
                "checkUrl=\"'descriptorByName/hudson.tasks.test.AggregatedTestResultPublisher/check?value='+encodeURIComponent(this.value)\"\n" +
                "field=\"jobs\"\n" +
                "autoCompleteDelimChar=\",\" />",
                Scanner.JELLY_PATTERNS,
                "checkUrl=\"'descriptorByName/hudson.tasks.test.AggregatedTestResultPublisher/check?value='+encodeURIComponent(this.value)\"");
    }

    @Test
    public void issues3_4_5() {
        final String scriptBlock = "<script>\nfoo bar\n baz \n</script>";
        assertMatch(scriptBlock, Scanner.JELLY_PATTERNS, scriptBlock);
        assertMatch("<some><wrapper>\n" + scriptBlock + "\n</wrapper></some>", Scanner.JELLY_PATTERNS, scriptBlock);

        assertMatches("<some><wrapper>\n" + scriptBlock + "\n" + scriptBlock + "</wrapper></some>", Scanner.JELLY_PATTERNS, List.of(scriptBlock, scriptBlock));

        assertNoMatch("<foo><script src='whatever'/></foo>", Scanner.JELLY_PATTERNS);
        assertMatch("<foo><script src='whatever' />" + scriptBlock + "</foo>", Scanner.JELLY_PATTERNS, scriptBlock);
    }

    private static void assertMatch(String haystack, Map<String, Pattern> patterns, String expectedMatch) {
        final File dummy = new File("dummy");
        final List<Scanner.Match> matches = Scanner.matchRegexes(patterns, haystack, dummy);
        assertThat(matches.size(), is(1));
        final Scanner.Match matchEntry = matches.get(0);
        assertThat(matchEntry.match, is(expectedMatch));
    }

    private static void assertMatches(String haystack, Map<String, Pattern> patterns, List<String> expectedMatches) {
        final File dummy = new File("dummy");
        final List<Scanner.Match> matches1 = Scanner.matchRegexes(patterns, haystack, dummy);
        assertThat(expectedMatches.size(), is(expectedMatches.size()));
        final List<String> actualMatches = matches1.stream().map(m -> m.match).collect(Collectors.toList());
        assertThat(actualMatches, contains(expectedMatches.stream().map(CoreMatchers::is).collect(Collectors.toList())));
    }

    private static void assertNoMatch(String haystack, Map<String, Pattern> patterns) {
        final List<Scanner.Match> matches = Scanner.matchRegexes(patterns, haystack, new File("dummy"));
        assertThat(matches.size(), is(0));
    }
}
