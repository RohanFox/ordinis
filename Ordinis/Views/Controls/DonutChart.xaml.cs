using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Shapes;

namespace Ordinis.Views.Controls;

public partial class DonutChart : UserControl
{
    public static readonly DependencyProperty PercentageProperty =
        DependencyProperty.Register(nameof(Percentage), typeof(double), typeof(DonutChart),
            new PropertyMetadata(0.0, OnPercentageChanged));

    public double Percentage
    {
        get => (double)GetValue(PercentageProperty);
        set => SetValue(PercentageProperty, value);
    }

    private static void OnPercentageChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
        => ((DonutChart)d).UpdateChart();

    public DonutChart()
    {
        InitializeComponent();
        Loaded += (_, _) => UpdateChart();
    }

    private void UpdateChart()
    {
        const double cx = 90, cy = 90, radius = 72;
        BackgroundPath.Data = CreateArc(cx, cy, radius, 0, 359.99);

        double angle = Math.Clamp(Percentage, 0, 100) / 100.0 * 360.0;
        ProgressPath.Data = angle < 0.5 ? Geometry.Empty : CreateArc(cx, cy, radius, 0, angle);

        // Update color based on score
        ProgressPath.Stroke = Percentage >= 80
            ? new SolidColorBrush(Color.FromRgb(34, 197, 94))   // green
            : Percentage >= 50
                ? new SolidColorBrush(Color.FromRgb(245, 158, 11)) // amber
                : new SolidColorBrush(Color.FromRgb(239, 68, 68)); // red

        PercentText.Text = $"{Percentage:F0}%";
    }

    private static Geometry CreateArc(double cx, double cy, double r, double startDeg, double endDeg)
    {
        double startRad = (startDeg - 90) * Math.PI / 180;
        double endRad   = (endDeg   - 90) * Math.PI / 180;

        var startPt = new Point(cx + r * Math.Cos(startRad), cy + r * Math.Sin(startRad));
        var endPt   = new Point(cx + r * Math.Cos(endRad),   cy + r * Math.Sin(endRad));

        bool isLargeArc = endDeg - startDeg > 180;

        var figure = new PathFigure { StartPoint = startPt, IsClosed = false };
        figure.Segments.Add(new ArcSegment(endPt, new Size(r, r), 0, isLargeArc, SweepDirection.Clockwise, true));
        return new PathGeometry(new[] { figure });
    }
}
