//! Line charts drawn on the server as inline SVG, so they need no script
//! and fit the strict Content-Security-Policy. Each point has a hover
//! target whose data-tip names the time and every series' value, and each
//! chart has a table with the same numbers.

/// One series: its name for the legend and tooltips, its color class
/// (c1, c2 or c3) and one value per bucket.
pub struct Series {
    pub name: &'static str,
    pub class: &'static str,
    pub values: Vec<u64>,
}

/// Round axis steps for a largest value (Heckbert's nice numbers): 1, 2 or
/// 5 times a power of ten, about four of them; never a fraction.
pub fn ticks(max: u64) -> Vec<u64> {
    if max == 0 {
        return vec![0, 1];
    }
    let rough = max.div_ceil(4).max(1);
    let mut power = 1u64;
    while power.saturating_mul(10) <= rough {
        power *= 10;
    }
    let mut step = 10 * power;
    for m in [1, 2, 5] {
        if m * power >= rough {
            step = m * power;
            break;
        }
    }
    (0..=max.div_ceil(step)).map(|i| i * step).collect()
}

/// How long before the end a bucket starts, in words: "Now", "3 hours ago",
/// "2 days ago".
pub fn ago_label(seconds_before_end: u64) -> String {
    match seconds_before_end {
        0..3600 => "Now".into(),
        3600..86_400 => {
            let h = seconds_before_end / 3600;
            format!("{h} {} ago", if h == 1 { "hour" } else { "hours" })
        }
        _ => {
            let d = seconds_before_end / 86_400;
            format!("{d} {} ago", if d == 1 { "day" } else { "days" })
        }
    }
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// The chart's SVG, drawn `width` units wide so its text stays readable at
/// about that many pixels; `class` names the variant (wide or narrow) the
/// stylesheet shows for the card's width. `labels` names each bucket for
/// its tooltip and the axis, and every series has one value per label;
/// `title` is read out for the whole chart.
pub fn lines(title: &str, labels: &[String], series: &[Series], width: f64, class: &str) -> String {
    const H: f64 = 200.0;
    const LEFT: f64 = 40.0;
    const BOTTOM: f64 = 22.0;
    const TOP: f64 = 8.0;
    let w = width;
    let n = labels.len();
    let max = series.iter().flat_map(|s| s.values.iter().copied()).fold(0, u64::max);
    let ticks = ticks(max);
    let top_value = ticks.iter().copied().fold(1, u64::max) as f64;
    let plot_w = w - LEFT;
    let plot_h = H - BOTTOM - TOP;
    let x = |i: usize| if n <= 1 { LEFT + plot_w / 2.0 } else { LEFT + plot_w * i as f64 / (n - 1) as f64 };
    let y = |v: u64| TOP + plot_h - plot_h * v as f64 / top_value;
    let mut svg = format!(r#"<svg class="{class}" viewBox="0 0 {w} {H}" role="img" aria-label="{}">"#, escape(title));
    for t in &ticks {
        let ty = y(*t);
        svg.push_str(&format!(
            r#"<line class="grid" x1="{LEFT}" x2="{w}" y1="{ty:.1}" y2="{ty:.1}"/><text class="tick end" x="{:.1}" y="{:.1}">{t}</text>"#,
            LEFT - 6.0,
            ty + 4.0
        ));
    }
    let base = TOP + plot_h;
    svg.push_str(&format!(r#"<line class="base" x1="{LEFT}" x2="{w}" y1="{base:.1}" y2="{base:.1}"/>"#));
    if n > 0 {
        let marks: &[(usize, &str)] = if w < 400.0 { &[(0, "tick"), (n - 1, "tick end")] } else { &[(0, "tick"), (n / 2, "tick mid"), (n - 1, "tick end")] };
        for (i, anchor) in marks {
            svg.push_str(&format!(r#"<text class="{anchor}" x="{:.1}" y="{H}">{}</text>"#, x(*i), escape(&labels[*i])));
        }
    }
    for s in series {
        let points: Vec<String> = s.values.iter().enumerate().map(|(i, v)| format!("{:.1},{:.1}", x(i), y(*v))).collect();
        svg.push_str(&format!(r#"<polyline class="line {}" points="{}"/>"#, s.class, points.join(" ")));
    }
    let slot = if n <= 1 { plot_w } else { plot_w / (n - 1) as f64 };
    for (i, label) in labels.iter().enumerate() {
        let tip: Vec<String> =
            series.iter().filter_map(|s| s.values.get(i).map(|v| format!("{} {v}", s.name))).collect();
        svg.push_str(&format!(
            r#"<rect class="hit" x="{:.1}" y="{TOP}" width="{slot:.1}" height="{plot_h:.1}" data-tip="{}: {}"/>"#,
            x(i) - slot / 2.0,
            escape(label),
            escape(&tip.join(", "))
        ));
    }
    svg.push_str("</svg>");
    svg
}

/// One bar of a ranked chart: its label, value and color class.
pub struct Bar {
    pub label: String,
    pub value: u64,
    pub class: &'static str,
}

/// `label` cut to `max` characters with an ellipsis, for a narrow column;
/// the tooltip and the table show it whole.
fn short(label: &str, max: usize) -> String {
    if label.chars().count() <= max {
        return label.to_string();
    }
    let mut out: String = label.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// A ranked bar chart in the order given, drawn `width` units wide: bars 16
/// units thick, square at the axis and rounded at the data end, each value
/// written beside its bar, and a hover target per row naming its label and
/// value in `unit`.
pub fn bars(title: &str, items: &[Bar], unit: &str, width: f64, class: &str) -> String {
    const ROW: f64 = 28.0;
    const THICK: f64 = 16.0;
    let (label_w, label_chars) = if width < 400.0 { (96.0, 13) } else { (150.0, 22) };
    let area = width - label_w - 48.0;
    let h = ROW * items.len() as f64 + 4.0;
    let max = items.iter().map(|b| b.value).fold(1, u64::max) as f64;
    let mut svg = format!(r#"<svg class="{class}" viewBox="0 0 {width} {h}" role="img" aria-label="{}">"#, escape(title));
    for (i, b) in items.iter().enumerate() {
        let top = i as f64 * ROW + 2.0;
        let mid = top + ROW / 2.0;
        let len = (area * b.value as f64 / max).max(4.0);
        let y0 = mid - THICK / 2.0;
        svg.push_str(&format!(
            r#"<text class="tick end" x="{:.1}" y="{:.1}">{}</text>"#,
            label_w - 8.0,
            mid + 4.0,
            escape(&short(&b.label, label_chars))
        ));
        svg.push_str(&format!(
            r#"<path class="bar {}" d="M{label_w},{y0:.1}h{:.1}a4,4 0 0 1 4,4v{:.1}a4,4 0 0 1 -4,4h{:.1}z"/>"#,
            b.class,
            len - 4.0,
            THICK - 8.0,
            4.0 - len
        ));
        svg.push_str(&format!(r#"<text class="tick" x="{:.1}" y="{:.1}">{}</text>"#, label_w + len + 6.0, mid + 4.0, b.value));
        svg.push_str(&format!(
            r#"<rect class="hit" x="0" y="{top:.1}" width="{width}" height="{ROW}" data-tip="{}: {} {}"/>"#,
            escape(&b.label),
            b.value,
            escape(unit)
        ));
    }
    svg.push_str("</svg>");
    svg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_labels_are_shortened_for_the_chart_only() {
        assert_eq!(short("alice", 13), "alice");
        assert_eq!(short("a-very-long-account-name", 13), "a-very-long-…");
    }

    #[test]
    fn ticks_are_round() {
        assert_eq!(ticks(0), vec![0, 1]);
        assert_eq!(ticks(3), vec![0, 1, 2, 3]);
        assert_eq!(ticks(17), vec![0, 5, 10, 15, 20]);
        assert_eq!(ticks(230), vec![0, 100, 200, 300]);
    }

    #[test]
    fn labels_say_how_long_ago() {
        assert_eq!(ago_label(0), "Now");
        assert_eq!(ago_label(3600), "1 hour ago");
        assert_eq!(ago_label(7 * 86_400), "7 days ago");
    }
}
