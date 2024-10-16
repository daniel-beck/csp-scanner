package io.jenkins.security.csp;

import java.io.File;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

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

    private static void assertMatch(String haystack, Map<String, Pattern> patterns, String match) {
        final File dummy = new File("dummy");
        final List<Scanner.Match> matches = Scanner.matchRegexes(patterns, haystack, dummy);
        assertThat(matches.size(), is(1));
        final Scanner.Match matchEntry = matches.get(0);
        assertThat(matchEntry.match, is(match));
    }

    private static void assertNoMatch(String haystack, Map<String, Pattern> patterns) {
        final List<Scanner.Match> matches = Scanner.matchRegexes(patterns, haystack, new File("dummy"));
        assertThat(matches.size(), is(0));
    }
}
