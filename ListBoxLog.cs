using System;
using System.Drawing;
using System.Text;
using System.Windows.Forms;

namespace DifferentSLIAuto
{
    public class ListBoxLog : IDisposable
    {
        private const string DEFAULT_MESSAGE_FORMAT = "[{5}] : {8}";
        private const int DEFAULT_MAX_LINES_IN_LISTBOX = 2000;

        private bool _disposed;
        private ListBox _listBox;
        private string _messageFormat;
        private int _maxEntriesInListBox;
        private bool _canAdd;
        private bool _paused;

        public enum Level : int
        {
            Critical = 0,
            Error = 1,
            Warning = 2,
            Info = 3,
            Verbose = 4,
            Debug = 5,
            Success = 6
        };

        private void OnHandleCreated(object sender, EventArgs e)
        {
            _canAdd = true;
        }
        private void OnHandleDestroyed(object sender, EventArgs e)
        {
            _canAdd = false;
        }
        private void DrawItemHandler(object sender, DrawItemEventArgs e)
        {
            if (e.Index >= 0)
            {
                e.DrawBackground();
                e.DrawFocusRectangle();

                LogEvent logEvent = ((ListBox)sender).Items[e.Index] as LogEvent;

                // SafeGuard against wrong configuration of list box
                if (logEvent == null)
                {
                    logEvent = new LogEvent(Level.Critical, ((ListBox)sender).Items[e.Index].ToString());
                }

                Color color;
                switch (logEvent.Level)
                {
                    case Level.Critical:
                        color = Color.Yellow;
                        break;
                    case Level.Error:
                        color = Color.Red;
                        break;
                    case Level.Warning:
                        color = Color.Goldenrod;
                        break;
                    case Level.Info:
                        color = Color.Green;
                        break;
                    case Level.Verbose:
                        color = Color.Blue;
                        break;
                    case Level.Success:
                        color = Color.Black;
                        break;
                    default:
                        color = Color.Black;
                        break;
                }

                if (logEvent.Level == Level.Critical)
                {
                    e.Graphics.FillRectangle(new SolidBrush(Color.Red), e.Bounds);
                }
                else if (logEvent.Level == Level.Success)
                {
                    e.Graphics.FillRectangle(new SolidBrush(Color.GreenYellow), e.Bounds);
                }
                e.Graphics.DrawString(FormatALogEventMessage(logEvent, _messageFormat), new Font("Lucida Console", 8.25f, FontStyle.Regular), new SolidBrush(color), e.Bounds);
            }
        }
        private void KeyDownHandler(object sender, KeyEventArgs e)
        {
            if ((e.Modifiers == Keys.Control) && (e.KeyCode == Keys.C))
            {
                CopyToClipboard();
            }
        }
        private void CopyMenuOnClickHandler(object sender, EventArgs e)
        {
            CopyToClipboard();
        }
        private void CopyMenuPopupHandler(object sender, EventArgs e)
        {
            ContextMenu menu = sender as ContextMenu;
            if (menu != null)
            {
                menu.MenuItems[0].Enabled = (_listBox.SelectedItems.Count > 0);
            }
        }

        private class LogEvent
        {
            public LogEvent(Level level, string message)
            {
                EventTime = DateTime.Now;
                Level = level;
                Message = message;
            }

            public readonly DateTime EventTime;

            public readonly Level Level;
            public readonly string Message;
        }
        private void WriteEvent(LogEvent logEvent)
        {
            if ((logEvent != null) && (_canAdd))
            {
                _listBox.BeginInvoke(new AddALogEntryDelegate(AddALogEntry), logEvent);
            }
        }
        private delegate void AddALogEntryDelegate(object item);
        private void AddALogEntry(object item)
        {
            _listBox.Items.Add(item);

            if (_listBox.Items.Count > _maxEntriesInListBox)
            {
                _listBox.Items.RemoveAt(0);
            }

            if (!_paused) _listBox.TopIndex = _listBox.Items.Count - 1;
        }
        private string LevelName(Level level)
        {
            switch (level)
            {
                case Level.Critical: return "Critical";
                case Level.Error: return "Error";
                case Level.Warning: return "Warning";
                case Level.Info: return "Info";
                case Level.Verbose: return "Verbose";
                case Level.Debug: return "Debug";
                case Level.Success: return "Success";
                default: return string.Format("<value={0}>", (int)level);
            }
        }
        private string FormatALogEventMessage(LogEvent logEvent, string messageFormat)
        {
            string message = logEvent.Message;
            if (message == null) { message = "<NULL>"; }
            return string.Format(messageFormat,
                /* {0} */ logEvent.EventTime.ToString("yyyy-MM-dd HH:mm:ss.fff"),
                /* {1} */ logEvent.EventTime.ToString("yyyy-MM-dd HH:mm:ss"),
                /* {2} */ logEvent.EventTime.ToString("yyyy-MM-dd"),
                /* {3} */ logEvent.EventTime.ToString("HH:mm:ss.fff"),
                /* {4} */ logEvent.EventTime.ToString("HH:mm:ss"),

                /* {5} */ LevelName(logEvent.Level)[0],
                /* {6} */ LevelName(logEvent.Level),
                /* {7} */ (int)logEvent.Level,

                /* {8} */ message);
        }
        private void CopyToClipboard()
        {
            if (_listBox.SelectedItems.Count > 0)
            {
                StringBuilder selectedItemsAsText = new StringBuilder();
                selectedItemsAsText.Append("[CODE]");
                foreach (LogEvent logEvent in _listBox.SelectedItems)
                {
                    selectedItemsAsText.AppendLine(FormatALogEventMessage(logEvent, _messageFormat));
                }
                selectedItemsAsText.Append("[/CODE]");
                Clipboard.SetText(selectedItemsAsText.ToString());
            }
        }

        public ListBoxLog(ListBox listBox) : this(listBox, DEFAULT_MESSAGE_FORMAT, DEFAULT_MAX_LINES_IN_LISTBOX) { }
        public ListBoxLog(ListBox listBox, string messageFormat) : this(listBox, messageFormat, DEFAULT_MAX_LINES_IN_LISTBOX) { }
        public ListBoxLog(ListBox listBox, string messageFormat, int maxLinesInListbox)
        {
            _disposed = false;

            _listBox = listBox;
            _messageFormat = messageFormat;
            _maxEntriesInListBox = maxLinesInListbox;

            _paused = false;

            _canAdd = listBox.IsHandleCreated;

            _listBox.SelectionMode = SelectionMode.MultiExtended;

            _listBox.HandleCreated += OnHandleCreated;
            _listBox.HandleDestroyed += OnHandleDestroyed;
            _listBox.DrawItem += DrawItemHandler;
            _listBox.KeyDown += KeyDownHandler;

            MenuItem[] menuItems = new MenuItem[] { new MenuItem("Copy", new EventHandler(CopyMenuOnClickHandler)) };
            _listBox.ContextMenu = new ContextMenu(menuItems);
            _listBox.ContextMenu.Popup += new EventHandler(CopyMenuPopupHandler);

            _listBox.DrawMode = DrawMode.OwnerDrawFixed;
        }

        public void Log(string message) { Log(Level.Debug, message); }
        public void Log(string format, params object[] args) { Log(Level.Debug, (format == null) ? null : string.Format(format, args)); }
        public void Log(Level level, string format, params object[] args) { Log(level, (format == null) ? null : string.Format(format, args)); }
        public void Log(Level level, string message)
        {
            WriteEvent(new LogEvent(level, message));
        }

        public bool Paused
        {
            get { return _paused; }
            set { _paused = value; }
        }

        ~ListBoxLog()
        {
            if (!_disposed)
            {
                Dispose(false);
                _disposed = true;
            }
        }
        public void Dispose()
        {
            if (!_disposed)
            {
                Dispose(true);
                GC.SuppressFinalize(this);
                _disposed = true;
            }
        }
        private void Dispose(bool disposing)
        {
            if (_listBox != null)
            {
                _canAdd = false;

                _listBox.HandleCreated -= OnHandleCreated;
                _listBox.HandleCreated -= OnHandleDestroyed;
                _listBox.DrawItem -= DrawItemHandler;
                _listBox.KeyDown -= KeyDownHandler;

                _listBox.ContextMenu.MenuItems.Clear();
                _listBox.ContextMenu.Popup -= CopyMenuPopupHandler;
                _listBox.ContextMenu = null;

                _listBox.Items.Clear();
                _listBox.DrawMode = DrawMode.Normal;
                _listBox = null;
            }
        }
    }
}
