//! The columns a Microsoft Defender custom detection's output needs, by the
//! family of the advanced hunting tables its query reads: `Timestamp`, and
//! `DeviceId` and `ReportId` for a device table, `ObservationId` for an
//! observation table, and so on (`required_column_groups`).
//!
//! `validate query --live` checks the columns a query run on the tenant
//! returns (opentide-connectors); the offline checks of a block against its
//! query's inferred output (opentide-tide, #1885) read the same table.

/// The Defender XDR advanced hunting tables a custom detection names, with
/// their family (`DEFENDER_XDR_TABLES`).
pub const DEFENDER_XDR_TABLES: [(&str, &str); 33] = [
    ("DeviceEvents", "endpoint"),
    ("DeviceFileCertificateInfo", "endpoint"),
    ("DeviceFileEvents", "endpoint"),
    ("DeviceImageLoadEvents", "endpoint"),
    ("DeviceInfo", "endpoint"),
    ("DeviceLogonEvents", "endpoint"),
    ("DeviceNetworkEvents", "endpoint"),
    ("DeviceNetworkInfo", "endpoint"),
    ("DeviceProcessEvents", "endpoint"),
    ("DeviceRegistryEvents", "endpoint"),
    ("AlertEvidence", "alert"),
    ("AlertInfo", "alert"),
    ("CampaignInfo", "xdr"),
    ("EmailAttachmentInfo", "xdr"),
    ("EmailEvents", "xdr"),
    ("EmailPostDeliveryEvents", "xdr"),
    ("EmailUrlInfo", "xdr"),
    ("FileMaliciousContentInfo", "xdr"),
    ("MessageEvents", "xdr"),
    ("MessagePostDeliveryEvents", "xdr"),
    ("MessageUrlInfo", "xdr"),
    ("UrlClickEvents", "xdr"),
    ("AADSignInEventsBeta", "xdr"),
    ("AADSpnSignInEventsBeta", "xdr"),
    ("CloudAppEvents", "xdr"),
    ("EntraIdSignInEvents", "xdr"),
    ("EntraIdSpnSignInEvents", "xdr"),
    ("IdentityAccountInfo", "xdr"),
    ("IdentityDirectoryEvents", "xdr"),
    ("IdentityInfo", "xdr"),
    ("IdentityLogonEvents", "xdr"),
    ("IdentityQueryEvents", "xdr"),
    ("OAuthAppInfo", "xdr"),
];

const TIMESTAMP_COLUMNS: [&str; 2] = ["Timestamp", "TimeGenerated"];
const IMPACTED_ASSET_IDENTIFIER_COLUMNS: [&str; 14] = [
    "DeviceId",
    "DeviceName",
    "RemoteDeviceName",
    "RecipientEmailAddress",
    "SenderFromAddress",
    "SenderMailFromAddress",
    "SenderObjectId",
    "RecipientObjectId",
    "AccountObjectId",
    "AccountSid",
    "AccountUpn",
    "InitiatingProcessAccountSid",
    "InitiatingProcessAccountUpn",
    "InitiatingProcessAccountObjectId",
];

fn is_word(character: char) -> bool {
    character.is_alphanumeric() || character == '_'
}

/// The Defender XDR tables *query* names (`defender_xdr_tables_in_query`).
///
/// Comments and string literals are blanked with [`kql_code`], which reads a
/// string before a `//` inside it: `let u = "http://x"; DeviceEvents` names
/// `DeviceEvents`.
pub fn defender_xdr_tables_in_query(query: &str) -> Vec<String> {
    let query = kql_code(query);
    let mut tables: Vec<String> = Vec::new();
    let preceded_ok = |at: usize| {
        query.get(..at).is_some_and(|head| {
            head.chars()
                .next_back()
                .is_none_or(|c| !is_word(c) && c != '.')
        })
    };
    for (table, _) in DEFENDER_XDR_TABLES {
        let found = query.match_indices(table).any(|(at, _)| {
            let followed_ok = query
                .get(at + table.len()..)
                .is_some_and(|rest| rest.chars().next().is_none_or(|c| !is_word(c)));
            preceded_ok(at) && followed_ok
        });
        if found {
            tables.push(table.to_owned());
        }
    }
    let mut from = 0;
    while let Some(offset) = query.get(from..).and_then(|rest| rest.find("Observation")) {
        let at = from + offset;
        let rest = query.get(at + "Observation".len()..).unwrap_or_default();
        let tail: usize = rest
            .chars()
            .take_while(|&c| is_word(c))
            .map(char::len_utf8)
            .sum();
        if preceded_ok(at) && tail > 0 {
            let name = query
                .get(at..at + "Observation".len() + tail)
                .unwrap_or_default();
            if !name.is_empty()
                && name != "ObservationId"
                && !tables.iter().any(|known| known == name)
            {
                tables.push(name.to_owned());
            }
            from = at + "Observation".len() + tail;
        } else {
            from = at + "Observation".len();
        }
    }
    tables.sort();
    tables
}

/// The column groups a custom detection's output needs, each an OR group
/// (`required_column_groups`).
pub fn required_column_groups(query: &str) -> Vec<Vec<&'static str>> {
    let tables = defender_xdr_tables_in_query(query);
    let categories: Vec<&str> = tables
        .iter()
        .map(|table| {
            if table.starts_with("Observation") {
                "observation"
            } else {
                DEFENDER_XDR_TABLES
                    .iter()
                    .find(|(name, _)| name == table)
                    .map_or("xdr", |(_, category)| *category)
            }
        })
        .collect();
    let has = |category: &str| categories.contains(&category);
    let mut groups: Vec<Vec<&'static str>> = vec![if categories.is_empty() {
        TIMESTAMP_COLUMNS.to_vec()
    } else {
        vec!["Timestamp"]
    }];
    if has("endpoint") {
        groups.push(vec!["DeviceId"]);
        groups.push(vec!["ReportId"]);
    }
    if has("observation") {
        groups.push(vec!["ObservationId"]);
    }
    if (has("xdr") || categories.is_empty()) && !groups.iter().any(|group| group == &["ReportId"]) {
        groups.push(vec!["ReportId"]);
    }
    if !has("endpoint") {
        groups.push(IMPACTED_ASSET_IDENTIFIER_COLUMNS.to_vec());
    }
    groups
}

/// The groups none of whose columns *returned* holds, each as `A or B`
/// (`missing_required_column_groups`).
pub fn missing_required_column_groups(query: &str, returned: &[&str]) -> Vec<String> {
    required_column_groups(query)
        .into_iter()
        .filter(|group| !group.iter().any(|column| returned.contains(column)))
        .map(|mut group| {
            group.sort_unstable();
            group.join(" or ")
        })
        .collect()
}

/// *query* with its `//` comments and string literals blanked, positions
/// (characters) kept (`query.runner.kql_code`). Kusto has no `/* */`
/// comments, so those stay code.
pub fn kql_code(query: &str) -> String {
    let chars: Vec<char> = query.chars().collect();
    let length = chars.len();
    let mut out = String::with_capacity(query.len());
    let mut index = 0;
    while index < length {
        let character = chars[index];
        if character == '/' && chars.get(index + 1) == Some(&'/') {
            let end = chars[index..]
                .iter()
                .position(|&c| c == '\n')
                .map_or(length, |offset| index + offset);
            out.extend(std::iter::repeat_n(' ', end - index));
            index = end;
            continue;
        }
        // A multi-line string (```…``` or ~~~…~~~) has no escapes and ends at
        // the next chord of the same kind (the Kusto grammar's `KqlTokens.g4`).
        if (character == '`' || character == '~')
            && chars.get(index + 1) == Some(&character)
            && chars.get(index + 2) == Some(&character)
        {
            let end = chars[index + 3..]
                .windows(3)
                .position(|chord| chord.iter().all(|&c| c == character))
                .map_or(length, |offset| index + 3 + offset + 3);
            out.extend(std::iter::repeat_n(' ', end - index));
            index = end;
            continue;
        }
        if character == '\'' || character == '"' {
            // A verbatim string (`@"C:\"`) has no escapes: a quote inside
            // it is doubled (`@"say ""hi"""`).
            let verbatim = index > 0 && chars[index - 1] == '@';
            let mut end = index + 1;
            while end < length {
                if chars[end] == character {
                    if verbatim && chars.get(end + 1) == Some(&character) {
                        end += 2;
                        continue;
                    }
                    break;
                }
                end += if chars[end] == '\\' && !verbatim {
                    2
                } else {
                    1
                };
            }
            let end = (end + 1).min(length);
            out.extend(std::iter::repeat_n(' ', end - index));
            index = end;
            continue;
        }
        out.push(character);
        index += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_double_slash_in_a_string_does_not_hide_the_table() {
        // `validate query --live` passed this query: the URL's `//` blanked
        // the rest of the query as a comment, so no table was found and the
        // endpoint columns were not required.
        let returned = ["Timestamp", "ReportId", "DeviceName"];
        assert_eq!(
            missing_required_column_groups(
                "let u = \"http://x\"; DeviceNetworkEvents | where RemoteUrl == u \
                 | project Timestamp, ReportId, DeviceName",
                &returned
            ),
            ["DeviceId"]
        );
        // A verbatim string has no escapes, and doubles a quote inside it.
        assert_eq!(
            missing_required_column_groups(
                r#"let u = @"\\host//share\"; DeviceFileEvents | project Timestamp, ReportId, DeviceName"#,
                &returned
            ),
            ["DeviceId"]
        );
        assert_eq!(
            defender_xdr_tables_in_query(
                r#"let p = @'C:\'; let q = @"//a""\"; EmailEvents | where 'b//' != p"#
            ),
            ["EmailEvents"]
        );
        // An escaped quote does not end a string; a comment still hides a table.
        assert_eq!(
            defender_xdr_tables_in_query(r#"print "a\"// DeviceEvents" // AlertInfo"#),
            Vec::<String>::new()
        );
        // A multi-line string has no escapes and ends at its own chord.
        assert_eq!(
            missing_required_column_groups(
                "let s = ```http://x```; DeviceEvents | project Timestamp, ReportId, DeviceName",
                &returned
            ),
            ["DeviceId"]
        );
        assert_eq!(
            defender_xdr_tables_in_query("let s = ~~~a```//~~~; EmailEvents | take 1"),
            ["EmailEvents"]
        );
        // Kusto has no block comments: a table inside `/* */` is read as
        // code, so its columns are required (the check fails closed).
        assert_eq!(
            defender_xdr_tables_in_query("/* DeviceEvents */ print 1"),
            ["DeviceEvents"]
        );
    }

    #[test]
    fn column_groups_follow_the_tables_the_query_names() {
        assert_eq!(
            missing_required_column_groups(
                "DeviceProcessEvents | project Timestamp, DeviceName",
                &["Timestamp", "DeviceName"]
            ),
            ["DeviceId", "ReportId"]
        );
        // A table named in a comment or a string is not one the query reads.
        assert_eq!(
            defender_xdr_tables_in_query("// EmailEvents\nT | where x == 'DeviceEvents'"),
            Vec::<String>::new()
        );
        assert_eq!(
            defender_xdr_tables_in_query("ObservationFoo | join ObservationId x.DeviceEvents"),
            ["ObservationFoo"]
        );
        assert_eq!(
            missing_required_column_groups("print 1", &[]),
            [
                "TimeGenerated or Timestamp",
                "ReportId",
                "AccountObjectId or AccountSid or AccountUpn or DeviceId or DeviceName or InitiatingProcessAccountObjectId or InitiatingProcessAccountSid or InitiatingProcessAccountUpn or RecipientEmailAddress or RecipientObjectId or RemoteDeviceName or SenderFromAddress or SenderMailFromAddress or SenderObjectId"
            ]
        );
    }

    #[test]
    fn multi_byte_words_around_table_names() {
        // #1946: the word-boundary checks and the `Observation*` scan never
        // slice inside a character.
        assert_eq!(
            defender_xdr_tables_in_query(
                "é DeviceEvents | union ObservationÉ, Observation😀, éDeviceInfo, DeviceLogonEventsé"
            ),
            ["DeviceEvents", "ObservationÉ"]
        );
    }
}
