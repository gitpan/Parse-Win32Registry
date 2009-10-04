#!/usr/bin/perl
use strict;
use warnings;

use constant MAX_SCALE => 10; # maximum scale for hbin maps

use Glib ':constants';
use Gtk2 -init;

my $screen = Gtk2::Gdk::Screen->get_default;
my $window_width = $screen->get_width * 0.9;
my $window_height = $screen->get_height * 0.8;
$window_width = 1100 if $window_width > 1100;
$window_height = 900 if $window_height > 900;

use Encode;
use File::Basename;
use Parse::Win32Registry 0.51 qw(hexdump qquote :REG_);

binmode(STDOUT, ':utf8');

my $script_name = basename $0;

### LIST VIEW

use constant {
    COLUMN_HBIN_OFFSET => 0,
    COLUMN_HBIN_OBJECT => 1,
};

my $hbin_store = Gtk2::ListStore->new(
    'Glib::String', 'Glib::Scalar',
);

my $hbin_view = Gtk2::TreeView->new($hbin_store);
$hbin_view->set_size_request(120, -1);

my $hbin_column1 = Gtk2::TreeViewColumn->new_with_attributes(
    'Hbin', Gtk2::CellRendererText->new,
    'text', COLUMN_HBIN_OFFSET,
);
$hbin_view->append_column($hbin_column1);
$hbin_column1->set_resizable(TRUE);

my $hbin_selection = $hbin_view->get_selection;
$hbin_selection->set_mode('browse');
$hbin_selection->signal_connect('changed' => \&hbin_selection_changed);

my $scrolled_hbin_view = Gtk2::ScrolledWindow->new;
$scrolled_hbin_view->set_policy('automatic', 'automatic');
$scrolled_hbin_view->set_shadow_type('in');
$scrolled_hbin_view->add($hbin_view);

### LIST VIEW FOR ENTRY

use constant {
    COLUMN_ENTRY_OFFSET => 0,
    COLUMN_ENTRY_LENGTH => 1,
    COLUMN_ENTRY_TAG => 2,
    COLUMN_ENTRY_IN_USE => 3,
    COLUMN_ENTRY_COLOR => 4,
    COLUMN_ENTRY_OBJECT => 5,
    COLUMN_ENTRY_USED_BY => 6,
};

my $entry_store = Gtk2::ListStore->new(
    'Glib::String', 'Glib::String', 'Glib::String',
    'Glib::String', 'Glib::String', 'Glib::Scalar',
    'Glib::String',
);

my $entry_view = Gtk2::TreeView->new($entry_store);

my $entry_column0 = Gtk2::TreeViewColumn->new_with_attributes(
    'Entry', my $entry_cell0 = Gtk2::CellRendererText->new,
    'text', COLUMN_ENTRY_OFFSET,
    'background', COLUMN_ENTRY_COLOR,
);
$entry_view->append_column($entry_column0);
$entry_column0->set_resizable(TRUE);

my $entry_column1 = Gtk2::TreeViewColumn->new_with_attributes(
    'Tag', my $entry_cell1 = Gtk2::CellRendererText->new,
    'text', COLUMN_ENTRY_TAG,
    'background', COLUMN_ENTRY_COLOR,
);
$entry_view->append_column($entry_column1);
$entry_column1->set_resizable(TRUE);

my $entry_column2 = Gtk2::TreeViewColumn->new_with_attributes(
    'Alloc.', Gtk2::CellRendererText->new,
    'text', COLUMN_ENTRY_IN_USE,
    'background', COLUMN_ENTRY_COLOR,
);
$entry_view->append_column($entry_column2);
$entry_column2->set_resizable(TRUE);

my $entry_column3 = Gtk2::TreeViewColumn->new_with_attributes(
    'Length', Gtk2::CellRendererText->new,
    'text', COLUMN_ENTRY_LENGTH,
    'background', COLUMN_ENTRY_COLOR,
);
$entry_view->append_column($entry_column3);
$entry_column3->set_resizable(TRUE);

my $entry_column4 = Gtk2::TreeViewColumn->new_with_attributes(
    'Owner', my $entry_cell4 = Gtk2::CellRendererText->new,
    'text', COLUMN_ENTRY_USED_BY,
    'background', COLUMN_ENTRY_COLOR,
);
$entry_view->append_column($entry_column4);
$entry_column4->set_resizable(TRUE);

my $entry_selection = $entry_view->get_selection;
$entry_selection->set_mode('browse');
$entry_selection->signal_connect('changed' => \&entry_selection_changed);

my $scrolled_entry_view = Gtk2::ScrolledWindow->new;
$scrolled_entry_view->set_policy('automatic', 'automatic');
$scrolled_entry_view->set_shadow_type('in');
$scrolled_entry_view->add($entry_view);

### TEXT VIEW

my $text_view = Gtk2::TextView->new;
$text_view->set_editable(FALSE);
$text_view->modify_font(Gtk2::Pango::FontDescription->from_string('monospace'));

my $text_buffer = $text_view->get_buffer;

my $scrolled_text_view = Gtk2::ScrolledWindow->new;
$scrolled_text_view->set_policy('automatic', 'automatic');
$scrolled_text_view->set_shadow_type('in');
$scrolled_text_view->add($text_view);

### IMAGE

my $hbin_image = Gtk2::Image->new;
my $eventbox = Gtk2::EventBox->new;
$eventbox->add($hbin_image);
$eventbox->add_events(['button-press-mask']);

$eventbox->signal_connect('button-press-event' => \&hbin_map_click);

my $scrolled_hbin_image = Gtk2::ScrolledWindow->new;
$scrolled_hbin_image->set_policy('automatic', 'automatic');
$scrolled_hbin_image->set_shadow_type('in');
$scrolled_hbin_image->add_with_viewport($eventbox);

### NOTEBOOK

my $notebook = Gtk2::Notebook->new;
my $hbin_map_page = $notebook->append_page($scrolled_hbin_image,
			Gtk2::Label->new_with_mnemonic("Hbin _Map"));
my $info_page = $notebook->append_page($scrolled_text_view,
			Gtk2::Label->new_with_mnemonic("_Info"));

### HPANED

my $hpaned = Gtk2::HPaned->new;
$hpaned->add1($scrolled_entry_view);
$hpaned->add2($notebook);
$hpaned->set_position(320);

### HBOX

my $hbox = Gtk2::HBox->new;
$hbox->pack_start($scrolled_hbin_view, FALSE, FALSE, 0);
$hbox->pack_start($hpaned, TRUE, TRUE, 0);

### UIMANAGER

my $uimanager = Gtk2::UIManager->new;

my @actions = (
    # name, stock id, label
    ['FileMenu', undef, '_File'],
    ['SearchMenu', undef, '_Search'],
    ['ViewMenu', undef, '_View'],
    ['HelpMenu', undef, '_Help'],
    # name, stock-id, label, accelerator, tooltip, callback
    ['Open', 'gtk-open', '_Open', '<control>O', undef, \&open_file],
    ['Quit', 'gtk-quit', '_Quit', '<control>Q', undef, \&quit],
    ['About', 'gtk-about', '_About', undef, undef, \&about],
);

my $default_actions = Gtk2::ActionGroup->new('actions');
$default_actions->add_actions(\@actions, undef);

my @actions2 = (
    # name, stock-id, label, accelerator, tooltip, callback
    ['Close', 'gtk-close', '_Close', '<control>W', undef, \&close_file],
    ['Find', 'gtk-find', '_Find', '<control>F', undef, \&find],
    ['FindNext', undef, 'Find _Next', '<control>G', undef, \&find_next],
    ['FindNext2', undef, undef, 'F3', undef, \&find_next],
    ['Process1', undef, '_Scan Entries', undef, undef, \&scan_entries],
    ['Process2', 'gtk-media-play', 'Identify _Entry Owners', '<control>E', undef, \&scan_tree],
    ['GoTo', 'gtk-index', '_Go To Offset', '<control>I', undef, \&go_to_offset],
);

my $file_actions = Gtk2::ActionGroup->new('actions2');
$file_actions->add_actions(\@actions2, undef);

my @actions3 = (
    # name, stock-id, label, accelerator, tooltip, callback
    ['ZoomIn', 'gtk-zoom-in', 'Zoom Hbin Map _In', '<control>plus', undef, \&zoom_in],
    ['ZoomIn2', undef, undef, '<control>equal', undef, \&zoom_in],
    ['ZoomOut', 'gtk-zoom-out', 'Zoom Hbin Map _Out', '<control>minus', undef, \&zoom_out],
    ['ZoomFit', 'gtk-zoom-fit', 'Zoom Hbin Map To _Fit', '<control>0', undef, \&zoom_fit],
    ['SaveHbinMap', 'gtk-save', '_Save Hbin Map', '<control>S', undef, \&save_hbin_map],
);

my $hbin_actions = Gtk2::ActionGroup->new('actions3');
$hbin_actions->add_actions(\@actions3, undef);

my @actions4 = (
    # name, stock-id, label, accelerator, tooltip, callback
    ['Jump', 'gtk-jump-to', '_Jump To Owner', '<control>J', undef, \&jump_to_owner],
    ['JumpBack', 'gtk-go-back', 'Jump _Back', 'BackSpace', undef, \&jump_back],
);

my $owner_actions = Gtk2::ActionGroup->new('actions4');
$owner_actions->add_actions(\@actions4, undef);

my @toggle_actions = (
    # name, stock id, label, accelerator, tooltip, callback, active
    ['ShowToolbar', undef, 'Show _Toolbar', '<control>T', undef, \&toggle_toolbar, TRUE],
    ['ShowHbins', undef, 'Show _Hbins', undef, undef, \&toggle_hbins, TRUE],
    ['ShowHbinMap', undef, 'Show Hbin _Map', undef, undef, \&toggle_hbin_map, TRUE],
);
$default_actions->add_toggle_actions(\@toggle_actions, undef);

$uimanager->insert_action_group($default_actions, 0);
$uimanager->insert_action_group($file_actions, 0);
$uimanager->insert_action_group($hbin_actions, 0);
$uimanager->insert_action_group($owner_actions, 0);

$file_actions->set_sensitive(FALSE);
$hbin_actions->set_sensitive(FALSE);
$owner_actions->set_sensitive(FALSE);

my $ui_info = <<END_OF_UI;
<ui>
    <menubar name='MenuBar'>
        <menu action='FileMenu'>
            <menuitem action='Open'/>
            <menuitem action='SaveHbinMap'/>
            <menuitem action='Close'/>
            <separator/>
            <menuitem action='Quit'/>
        </menu>
        <menu action='SearchMenu'>
            <menuitem action='Find'/>
            <menuitem action='FindNext'/>
            <separator/>
            <menuitem action='GoTo'/>
            <separator/>
            <menuitem action='Process2'/>
            <menuitem action='Jump'/>
            <menuitem action='JumpBack'/>
        </menu>
        <menu action='ViewMenu'>
            <menuitem action='ShowToolbar'/>
            <menuitem action='ShowHbins'/>
            <menuitem action='ShowHbinMap'/>
            <separator/>
            <menuitem action='ZoomIn'/>
            <menuitem action='ZoomOut'/>
            <menuitem action='ZoomFit'/>
        </menu>
        <menu action='HelpMenu'>
            <menuitem action='About'/>
        </menu>
    </menubar>
    <toolbar name='ToolBar'>
        <toolitem action='Open'/>
        <toolitem action='Close'/>
        <separator/>
        <toolitem action='Find'/>
        <toolitem action='GoTo'/>
        <toolitem action='Jump'/>
        <separator/>
        <toolitem action='Quit'/>
    </toolbar>
    <accelerator action='FindNext2'/>
    <accelerator action='ZoomIn2'/>
</ui>
END_OF_UI

$uimanager->add_ui_from_string($ui_info);

my $menubar = $uimanager->get_widget('/MenuBar');
my $toolbar = $uimanager->get_widget('/ToolBar');

### STATUSBAR

my $statusbar = Gtk2::Statusbar->new;

### VBOX

my $main_vbox = Gtk2::VBox->new(FALSE, 0);
$main_vbox->pack_start($menubar, FALSE, FALSE, 0);
$main_vbox->pack_start($toolbar, FALSE, FALSE, 0);
$main_vbox->pack_start($hbox, TRUE, TRUE, 0);
$main_vbox->pack_start($statusbar, FALSE, FALSE, 0);

### WINDOW

my $window = Gtk2::Window->new;
$window->set_default_size($window_width, $window_height);
$window->set_position('center');
$window->signal_connect(destroy => sub { Gtk2->main_quit });
$window->add($main_vbox);
$window->add_accel_group($uimanager->get_accel_group);
$window->set_title($script_name);
$window->show_all;

my $filename = shift;
if (defined $filename && -r $filename) {
    load_file($filename);
}

### GLOBALS

my $registry;

my $last_dir;

my $find_param = '';
my $find_iter;
my $find_hbin;
my $find_hbin_iter;
my $find_entry_iter;

my $entry_source; # will be a registry for Win95, a hbin for WinNT

my $map_width;
my $map_height;
my $map_pixbuf;
my $map_scale = 6;

my %owners = ();

my @jump_history = ();

Gtk2->main;

###############################################################################

sub load_entries {
    return if !defined $entry_source;

    $entry_store->clear;

    # $entry_source is either a WinNT::Hbin or a Win95::File.
    my $entry_iter = $entry_source->get_entry_iterator;
    while (my $entry = $entry_iter->get_next) {
        my $iter = $entry_store->append;

        my $tag = $entry->get_tag;
        my $offset = $entry->get_offset;

        # colorize each row according to its tag (NT only)
        # '#FF8080' red, sat 50%
        # '#80FFFF' cyan, sat 50%
        # '#80FF80' green, sat 50%
        # '#FF80FF' magenta, sat 50%
        my $color = '#E6E6E6';
        if ($tag eq 'nk') {
            $color = '#FF8080';
        }
        elsif ($tag eq 'sk') {
            $color = '#80FFFF';
        }
        elsif ($tag eq 'vk') {
            $color = '#80FF80';
        }
        elsif ($tag =~ /(lf|lh|li|ri)/) {
            $color = '#FF80FF';
        }

        $entry_store->set($iter,
            COLUMN_ENTRY_OFFSET, sprintf("0x%x", $offset),
            COLUMN_ENTRY_LENGTH, $entry->get_length,
            COLUMN_ENTRY_TAG, $tag,
            COLUMN_ENTRY_IN_USE, $entry->is_allocated,
            COLUMN_ENTRY_COLOR, $color,
            COLUMN_ENTRY_OBJECT, $entry);

        # If owners have been identified, add this to the Owner column
        if (exists $owners{$offset}) {
            my $desc = "";
            my $num_referrers = @{$owners{$offset}};
            if ($num_referrers == 1) {
                my $rtype = $owners{$offset}[0]{type};
                my $roffset = $owners{$offset}[0]{offset};
                $desc = sprintf "$rtype @ 0x%x", $roffset;
                if ($roffset == $offset) {
                    $desc = "Self";
                }
            }
            else {
                $desc = "$num_referrers referrers";
            }
            $entry_store->set($iter,
                COLUMN_ENTRY_USED_BY, $desc);
        }
    }
}

sub hbin_selection_changed {
    my ($model, $iter) = $hbin_selection->get_selected;
    if (!defined $model || !defined $iter) {
        return;
    }

    my $hbin = $model->get($iter, COLUMN_HBIN_OBJECT);
    $entry_source = $hbin; # set global entry source

    my $str = $hbin->parse_info . "\n";
    $str .= $hbin->unparsed;

    $text_buffer->set_text($str);

    $statusbar->pop(0);
    $statusbar->push(0, sprintf("Hbin @ 0x%x", $hbin->get_offset));

    load_entries();

    make_hbin_map();
    zoom_fit();

    $notebook->set_current_page($hbin_map_page);
}

sub entry_selection_changed {
    my ($model, $iter) = $entry_selection->get_selected;
    if (!defined $model || !defined $iter) {
        return;
    }

    my $entry = $model->get($iter, COLUMN_ENTRY_OBJECT);
    my $offset = $entry->get_offset;

    my $desc;
    if ($entry->looks_like_key) {
        $desc = sprintf "Key @ 0x%x", $offset;
    }
    elsif ($entry->looks_like_value) {
        $desc = sprintf "Value @ 0x%x", $offset;
    }
    elsif ($entry->looks_like_security) {
        $desc = sprintf "Security @ 0x%x", $offset;
    }
    else {
        $desc = sprintf "Entry @ 0x%x", $offset;
    }

    my $str = "$desc\n\n"
            . $entry->parse_info . "\n"
            . $entry->unparsed . "\n";

    my $status = $desc;

    if ($entry->looks_like_key) {
        $str .= $entry->as_string . "\n\n";
        $status .= ' "' . $entry->get_name . '"';
    }
    elsif ($entry->looks_like_value) {
        my $name = $entry->get_name;
        $name = '(Default)' if $name eq '';
        my $type_as_string = $entry->get_type_as_string;

        $str .= "$name ($type_as_string)\n\n";
        $status .= ' "' . $entry->get_name . '"';
    }

    $text_buffer->set_text($str);
    $notebook->set_current_page($info_page);

    $statusbar->pop(0);
    $statusbar->push(0, $status);
}

sub show_message {
    my $type = shift;
    my $message = shift;

    my $dialog = Gtk2::MessageDialog->new(
        $window,
        'destroy-with-parent',
        $type,
        'ok',
        $message,
    );
    $dialog->set_title(ucfirst $type);
    $dialog->run;
    $dialog->destroy;
}

sub load_file {
    my $filename = shift;

    my ($name, $path) = fileparse($filename);

    close_file();

    if (!-r $filename) {
        show_message('error', "Unable to open '$name'.");
    }
    elsif ($registry = Parse::Win32Registry->new($filename)) {
        if (my $root_key = $registry->get_root_key) {
            $window->set_title("$name - $script_name");

            my $hbin_iter = $registry->get_hbin_iterator;
            if (defined $hbin_iter) { # WinNT
                # load hbins
                while (my $hbin = $hbin_iter->get_next) {
                    my $iter = $hbin_store->append;
                    $hbin_store->set($iter,
                        COLUMN_HBIN_OFFSET, sprintf("0x%x", $hbin->{_offset}),
                        COLUMN_HBIN_OBJECT, $hbin);
                }
                show_hbin_functions(TRUE);
            }
            else { # Win95
                $entry_source = $registry;
                load_entries();
                show_hbin_functions(FALSE);
            }
            $file_actions->set_sensitive(TRUE);
        }
    }
    else {
        show_message('error', "'$name' is not a registry file.");
    }
}

sub choose_file {
    my ($title, $type, $suggested_name) = @_;

    my $file_chooser = Gtk2::FileChooserDialog->new(
        $title,
        undef,
        $type,
        'gtk-cancel' => 'cancel',
        'gtk-ok' => 'ok',
    );
    if ($type eq 'save') {
        $file_chooser->set_current_name($suggested_name);
    }
    if (defined $last_dir) {
        $file_chooser->set_current_folder($last_dir);
    }
    my $response = $file_chooser->run;

    my $filename;
    if ($response eq 'ok') {
        $filename = $file_chooser->get_filename;
    }
    $last_dir = $file_chooser->get_current_folder;
    $file_chooser->destroy;
    return $filename;
}

sub open_file {
    my $filename = choose_file('Select Registry File', 'open');
    if (defined $filename) {
        load_file($filename);
    }
}

sub save_hbin_map {
    return if !defined $map_pixbuf;

    my ($model, $iter) = $hbin_selection->get_selected;
    if (!defined $model || !defined $iter) {
        return;
    }

    my $hbin = $model->get($iter, COLUMN_HBIN_OBJECT);

    my $name = sprintf "hbin\@0x%x.jpg", $hbin->get_offset;

    my $filename = choose_file('Save Hbin Map', 'save', $name);
    if (defined $filename) {
        my $pixbuf = $map_pixbuf->scale_simple($map_width * MAX_SCALE,
                                               $map_height * MAX_SCALE,
                                               'tiles');
        $pixbuf->save($filename, 'jpeg', quality => 100);
    }
}

sub close_file {
    $hbin_store->clear;
    $entry_store->clear;
    $registry = undef;
    $entry_source = undef;
    $hbin_image->clear;
    $text_buffer->set_text('');
    $statusbar->pop(0);
    $map_pixbuf = undef;
    %owners = ();
    @jump_history = ();
    $file_actions->set_sensitive(FALSE);
    $hbin_actions->set_sensitive(FALSE);
    $owner_actions->set_sensitive(FALSE);
}

sub quit {
    $window->destroy;
}

sub about {
    Gtk2->show_about_dialog(undef,
        'program-name' => $script_name,
        'version' => $Parse::Win32Registry::VERSION,
        'copyright' => 'Copyright (c) 2009 James Macfarlane',
        'comments' => 'GTK2 Registry Scope for the Parse::Win32Registry module',
    );
}

sub toggle_hbins {
    my ($toggle_action) = @_;
    if ($toggle_action->get_active) {
        $scrolled_hbin_view->show;
    }
    else {
        $scrolled_hbin_view->hide;
    }
}

sub toggle_hbin_map {
    my ($toggle_action) = @_;
    if ($toggle_action->get_active) {
        $scrolled_hbin_image->show;
    }
    else {
        $scrolled_hbin_image->hide;
    }
}

sub toggle_toolbar {
    my ($toggle_action) = @_;
    if ($toggle_action->get_active) {
        $toolbar->show;
    }
    else {
        $toolbar->hide;
    }
}

sub make_hbin_map {
    my ($model, $iter) = $hbin_selection->get_selected;
    if (!defined $model || !defined $iter) {
        return;
    }

    my $hbin = $model->get($iter, COLUMN_HBIN_OBJECT);

    my $hbin_length = $hbin->get_length;

    # Find the nearest power of 2 larger than hbin length
    my $n = $hbin_length;
    if ($n > 0) {
        $n--;
        foreach (1..31) {
            $n |= $n >> $_;
        }
        $n++;
    }

    # Find the squarest map dimensions
    my $h = 1;
    my $w = $n;
    while ($h < $w) {
        $h *= 2;
        $w /= 2;
    }

    $map_width = $w;
    $map_height = int($hbin_length / $w);

    # Initialise the byte sequence with the hbin header
    my $data = pack "C*",
        map { ($_, $_, $_, 255) } unpack("C*", $hbin->get_raw_bytes);

    # Build the hbin map using colorised byte sequences
    my $entry_iter = $hbin->get_entry_iterator;
    while (my $entry = $entry_iter->get_next) {
        my $tag = $entry->get_tag;
        if ($tag eq 'nk') {
            $data .= pack "C*",
                map { ($_, 0, 0, 255) } unpack("C*", $entry->get_raw_bytes);
        }
        elsif ($tag eq 'vk') {
            $data .= pack "C*",
                map { (0, $_, 0, 255) } unpack("C*", $entry->get_raw_bytes);
        }
        elsif ($tag eq 'sk') {
            $data .= pack "C*",
                map { (0, $_, $_, 255) } unpack("C*", $entry->get_raw_bytes);
        }
        elsif ($tag =~ /(lf|lh|ri|li)/) {
            $data .= pack "C*",
                map { ($_, 0, $_, 255) } unpack("C*", $entry->get_raw_bytes);
        }
        else {
            $data .= pack "C*",
                map { ($_, $_, $_, 255) } unpack("C*", $entry->get_raw_bytes);
        }
    }

    my $padding = ($map_width * $map_height) - int(length($data) / 4);
    $data .= pack "C*", (255, 255, 255, 128) x $padding;

    $map_pixbuf = Gtk2::Gdk::Pixbuf->new_from_data(
        $data, 'rgb', 1, 8, $map_width, $map_height, $map_width * 4);
}

sub hbin_map_click {
    my ($widget, $event) = @_;

    my ($x, $y) = ($event->x, $event->y);

    my @alloc = $hbin_image->allocation->values;
    my $alloc_width = $alloc[2];
    my $alloc_height = $alloc[3];
    my $map_x = $x - ($alloc_width - $map_width*$map_scale) / 2;
    my $map_y = $y - ($alloc_height - $map_height*$map_scale) / 2;
    $map_x /= $map_scale;
    $map_y /= $map_scale;
    $map_x = int($map_x);
    $map_y = int($map_y);

    if (($map_x >= 0 && $map_x < $map_width) &&
        ($map_y >= 0 && $map_y < $map_height)) {
        my $offset = ($map_y * $map_width) + $map_x;

        my ($model, $iter) = $hbin_selection->get_selected;
        if (!defined $model || !defined $iter) {
            return;
        }
        my $hbin = $model->get($iter, COLUMN_HBIN_OBJECT);
        $offset += $hbin->get_offset;

        if ($offset < ($hbin->get_offset + 0x20)) {
            # First 32 bytes comprise the hbin header
            go_to_hbin($offset);
        }
        else {
            go_to_entry($offset);
            $notebook->set_current_page($hbin_map_page);
        }
    }
}

sub show_owner_functions {

}

sub show_hbin_functions {
    my $state = shift;

    my $show_hbins_toggle
        = $uimanager->get_widget('/MenuBar/ViewMenu/ShowHbins');

    my $show_hbin_map_toggle
        = $uimanager->get_widget('/MenuBar/ViewMenu/ShowHbinMap');

    if ($state) {
        $hbin_actions->set_sensitive(TRUE);
        $show_hbins_toggle->set_active(TRUE);
        $show_hbin_map_toggle->set_active(TRUE);
    }
    else {
        $hbin_actions->set_sensitive(FALSE);
        $show_hbins_toggle->set_active(FALSE);
        $show_hbin_map_toggle->set_active(FALSE);
    }
}

sub draw_scaled_map {
    return if !defined $map_pixbuf;

    my $scale = shift || $map_scale; # optional override

    my $pixbuf = $map_pixbuf->scale_simple($map_width * $scale,
                                           $map_height * $scale,
                                           'tiles');
    $hbin_image->set_from_pixbuf($pixbuf);
}

sub zoom_in {
    return if !defined $map_pixbuf;

    $map_scale++;
    $map_scale = MAX_SCALE if $map_scale > MAX_SCALE;
    draw_scaled_map();
    $notebook->set_current_page($hbin_map_page);
}

sub zoom_out {
    return if !defined $map_pixbuf;

    $map_scale--;
    $map_scale = 1 if $map_scale < 1;
    draw_scaled_map();
    $notebook->set_current_page($hbin_map_page);
}

sub zoom_fit {
    return if !defined $map_pixbuf;

    my $allocation = $scrolled_hbin_image->allocation;
    my ($x, $y, $available_width, $available_height) = $allocation->values;

    for (my $scale = MAX_SCALE; $scale > 0; $scale--) {
        my $width = $map_width * $scale;
        my $height = $map_height * $scale;

        if ($width < $available_width && $height < $available_height) {
            $map_scale = $scale;
            last;
        }
    }
    draw_scaled_map();
    $notebook->set_current_page($hbin_map_page);
}

sub go_to_hbin {
    my ($offset) = @_;

    my $iter = $hbin_store->get_iter_first;
    while (defined $iter) {
        my $hbin = $hbin_store->get($iter, COLUMN_HBIN_OBJECT);
        my $hbin_start = $hbin->get_offset;
        my $hbin_end = $hbin_start + $hbin->get_length;
        if ($offset >= $hbin_start && $offset < $hbin_end) {
            my $tree_path = $hbin_store->get_path($iter);
            $hbin_view->expand_to_path($tree_path);
            $hbin_view->scroll_to_cell($tree_path);
            $hbin_view->set_cursor($tree_path);
            $window->set_focus($hbin_view);
            return;
        }
        $iter = $hbin_store->iter_next($iter);
    }
}

sub go_to_entry {
    my ($offset) = @_;

    my $iter = $entry_store->get_iter_first;
    while (defined $iter) {
        my $entry = $entry_store->get($iter, COLUMN_ENTRY_OBJECT);
        my $entry_start = $entry->get_offset;
        my $entry_end = $entry_start + $entry->get_length;
        if ($offset >= $entry_start && $offset < $entry_end) {
            my $tree_path = $entry_store->get_path($iter);
            $entry_view->expand_to_path($tree_path);
            $entry_view->scroll_to_cell($tree_path);
            $entry_view->set_cursor($tree_path);
            $window->set_focus($entry_view);
            return;
        }
        $iter = $entry_store->iter_next($iter);
    }
}

sub find_next {
    if (!defined $find_param || !defined $find_entry_iter) {
        return;
    }

    # Build find next dialog
    my $label = Gtk2::Label->new;
    $label->set_text("Searching registry entries...");
    my $dialog = Gtk2::Dialog->new('Find',
        $window,
        'modal',
        'gtk-cancel' => 'cancel',
    );
    $dialog->vbox->pack_start($label, TRUE, TRUE, 5);
    $dialog->set_default_response('cancel');
    $dialog->show_all;

    my $id = Glib::Idle->add(sub {
        while (1) {
            my $entry = $find_entry_iter->get_next;
            if (defined $entry) {
                my $found = 0;

                if (index($entry->get_raw_bytes, $find_param) > -1) {
                    $found = 1;
                }
                else {
                    my $uni_find_param = encode("UCS-2LE", $find_param);
                    if (index($entry->get_raw_bytes, $uni_find_param) > -1) {
                        $found = 1;
                    }
                }

                if ($found) {
                    if (defined $find_hbin) {
                        go_to_hbin($find_hbin->get_offset);
                    }
                    go_to_entry($entry->get_offset);

                    $dialog->response(50);
                    return FALSE;
                }

                return TRUE; # continue searching...
            }
            else { # no more entries...?
                if (defined $find_hbin_iter) {
                    $find_hbin = $find_hbin_iter->get_next;
                    if (defined $find_hbin) {
                        $find_entry_iter = $find_hbin->get_entry_iterator;
                        if (!defined $find_entry_iter) {
                            last; # no entry iterator... (WinNT)
                        }
                    }
                    else {
                        last; # no more hbins... (WinNT)
                    }
                }
                else {
                    last; # no more entries... (Win95)
                }
            }
        }

        $dialog->response('ok');
        return FALSE;

    });

    my $response = $dialog->run;
    $dialog->destroy;

    if ($response eq 'cancel' || $response eq 'delete-event') {
        Glib::Source->remove($id);
    }
    elsif ($response eq 'ok') {
        show_message('info', 'Finished searching.');
    }
}

sub find {
    return if !defined $registry;

    my $entry = Gtk2::Entry->new;
    $entry->set_text($find_param);
    $entry->set_activates_default(TRUE);
    my $dialog = Gtk2::Dialog->new('Find',
        $window,
        'modal',
        'gtk-cancel' => 'cancel',
        'gtk-ok' => 'ok',
    );
    $dialog->vbox->pack_start($entry, TRUE, TRUE, 5);
    $dialog->set_default_response('ok');
    $dialog->show_all;

    my $response = $dialog->run;
    $dialog->destroy;

    if ($response eq 'ok') {
        $find_param = $entry->get_text;
        if ($find_param ne '') {
            # WinNT: initialise hbin_iter, hbin, entry_iter
            # Win95: initialise entry_iter
            $find_hbin_iter = $registry->get_hbin_iterator;
            if (defined $find_hbin_iter) { # WinNT
                $find_hbin = $find_hbin_iter->get_next;
                $find_entry_iter = $find_hbin->get_entry_iterator;
            }
            else { # Win95
                $find_entry_iter = $registry->get_entry_iterator;
            }
            find_next;
        }
    }
}

sub go_to_offset {
    return if !defined $registry;

    my $entry = Gtk2::Entry->new;
    $entry->set_activates_default(TRUE);
    my $dialog = Gtk2::Dialog->new('Go To Offset',
        $window,
        'modal',
        'gtk-cancel' => 'cancel',
        'gtk-ok' => 'ok',
    );
    $dialog->vbox->pack_start($entry, TRUE, TRUE, 5);
    $dialog->set_default_response('ok');
    $dialog->show_all;

    $entry->prepend_text("0x");
    $entry->set_position(-1);

    my $response = $dialog->run;
    $dialog->destroy;

    if ($response ne 'ok') {
        return;
    }

    my $offset;
    eval {
        my $answer = $entry->get_text;
        if ($answer =~ m/^0x[\da-fA-F]+\s*$/) {
            $offset = int(eval $answer);
        }
    };

    if (defined $offset && $offset < $registry->get_length) {
        go_to_hbin($offset);
        go_to_entry($offset);
    }
}

sub jump_to_owner {
    my ($model, $iter) = $entry_selection->get_selected;
    if (!defined $model || !defined $iter) {
        return;
    }

    if (!%owners) {
        show_message('error', "'Identify Entry Owners' has not been run.");
        return;
    }

    my $entry = $model->get($iter, COLUMN_ENTRY_OBJECT);
    my $offset = $entry->get_offset;

    if (exists $owners{$offset}) {
        my $num_referrers = @{$owners{$offset}};
        if ($num_referrers >= 1) {
            my $roffset = $owners{$offset}[0]{offset};
            if ($roffset != $offset) {
                push @jump_history, $offset;
                go_to_hbin($roffset);
                go_to_entry($roffset);
            }
        }
    }
}

sub jump_back {
    if (@jump_history) {
        my $offset = pop @jump_history;
        go_to_hbin($offset);
        go_to_entry($offset);
    }
}

###############################################################################

sub scan_entries {
    return if !defined $registry;

    my $label = Gtk2::Label->new;
    $label->set_text("Searching registry...");
    my $dialog = Gtk2::Dialog->new('Find',
        $window,
        'modal',
        'gtk-cancel' => 'cancel',
    );
    $dialog->vbox->pack_start($label, TRUE, TRUE, 5);
    $dialog->set_default_response('cancel');
    $dialog->show_all;

    my $entry_iter;
    my $hbin_iter = $registry->get_hbin_iterator;
    if (defined $hbin_iter) { # WinNT
        my $hbin = $hbin_iter->get_next;
        $entry_iter = $hbin->get_entry_iterator;
    }
    else { # Win95
        $entry_iter = $registry->get_entry_iterator;
    }

    my $id = Glib::Idle->add(sub {
        while (1) {
            my $entry = $entry_iter->get_next;
            if (defined $entry) {

                # do something with entry...
                printf "processing entry 0x%x...\n", $entry->get_offset;

                return TRUE; # continue searching...
            }
            else { # no more entries...?
                if (defined $hbin_iter) {
                    my $hbin = $hbin_iter->get_next;
                    if (defined $hbin) {
                        $entry_iter = $hbin->get_entry_iterator;
                        if (!defined $entry_iter) {
                            last; # no more entries... (WinNT)
                        }
                    }
                    else {
                        last; # no more hbins... (WinNT)
                    }
                }
                else {
                    last; # no more entries... (Win95)
                }
            }
        }

        $dialog->response('ok');
        show_message('info', 'Finished long running process.');
        return FALSE;
    });

    my $response = $dialog->run;
    $dialog->destroy;

    if ($response eq 'cancel' || $response eq 'delete-event') {
        Glib::Source->remove($id);
    }
}

sub scan_tree {
    return if !defined $registry;

    %owners = ();

    my $label = Gtk2::Label->new;
    $label->set_text("Scanning registry to identify entry owners...");
    my $dialog = Gtk2::Dialog->new('Scanning',
        $window,
        'modal',
        'gtk-cancel' => 'cancel',
    );
    $dialog->vbox->pack_start($label, TRUE, TRUE, 5);
    $dialog->set_default_response('cancel');
    $dialog->show_all;

    my $root_key = $registry->get_root_key;
    my $subtree_iter = $root_key->get_subtree_iterator;
    my $value_iter;

    my $id = Glib::Idle->add(sub {
        if (defined $value_iter) {
            my $value = $value_iter->get_next;
            if (defined $value) {
                my $name = $value->get_name;
                $name = '(Default)' if $name eq '';

                my $self_offset = $value->get_offset;
                foreach my $offset ($value->get_associated_offsets) {
                    push @{$owners{$offset}},
                        { type => "Value", offset => $self_offset };
                }

                return TRUE; # continue processing
            }
        }
        if (defined $subtree_iter) {
            my $key = $subtree_iter->get_next;
            if (defined $key) {
                my $self_offset = $key->get_offset;
                foreach my $offset ($key->get_associated_offsets) {
                    push @{$owners{$offset}},
                        { type => "Key", offset => $self_offset };
                }

                # Fetch new value iterator for new key
                $value_iter = $key->get_value_iterator;
                return TRUE; # continue processing
            }
        }

        $dialog->response('ok');
        return FALSE; # stop processing
    });

    my $response = $dialog->run;
    $dialog->destroy;

    if ($response eq 'cancel' || $response eq 'delete-event') {
        Glib::Source->remove($id);
        %owners = ();
    }
    elsif ($response eq 'ok') {
        $entry_column4->set_visible(TRUE);
        show_message('info', "Finished identifying entry owners.\n"
                           . "Check the Owner column for details.");
        $owner_actions->set_sensitive(TRUE);
        load_entries();
    }
}

