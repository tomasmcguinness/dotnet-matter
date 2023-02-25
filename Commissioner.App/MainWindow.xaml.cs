// Copyright (c) Microsoft Corporation and Contributors.
// Licensed under the MIT License.

using Microsoft.UI.Xaml;
using Windows.Devices.Bluetooth.Advertisement;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace Commissioner.App
{
    /// <summary>
    /// An empty window that can be used on its own or navigated to within a Frame.
    /// </summary>
    public sealed partial class MainWindow : Window
    {
        private BluetoothLEAdvertisementWatcher _watcher;

        public MainWindow()
        {
            this.InitializeComponent();

            _watcher = new BluetoothLEAdvertisementWatcher();
            _watcher.Received += watcher_Received;
        }

        private void watcher_Received(BluetoothLEAdvertisementWatcher sender, BluetoothLEAdvertisementReceivedEventArgs args)
        {
            
        }

        private void myButton_Click(object sender, RoutedEventArgs e)
        {
            _watcher.Start();
        }
    }
}
