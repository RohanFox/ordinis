using System.Windows;
using Ordinis.ViewModels;

namespace Ordinis;

public partial class MainWindow : Window
{
    public MainViewModel VM { get; }

    // Expose for LoadingOverlay bindings
    public bool IsLoading  => VM.IsLoading;
    public string StatusText => VM.StatusText;
    public double Progress   => VM.Progress;

    public MainWindow()
    {
        InitializeComponent();
        VM          = new MainViewModel();
        DataContext = VM;

        VM.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName is nameof(VM.IsLoading) or nameof(VM.StatusText) or nameof(VM.Progress))
            {
                OnPropertyChanged(e.PropertyName == nameof(VM.IsLoading)  ? nameof(IsLoading)
                                : e.PropertyName == nameof(VM.StatusText) ? nameof(StatusText)
                                :                                            nameof(Progress));
            }
        };
    }

    private void OnPropertyChanged(string propertyName)
    {
        // Trigger binding updates on the window's dependency properties
        Dispatcher.InvokeAsync(() =>
        {
            if (propertyName == nameof(IsLoading))
                InvalidateProperty(DataContextProperty);
        });
    }
}
