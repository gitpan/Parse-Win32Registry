#!/usr/bin/perl
use strict;
use warnings;

use Glib ':constants';
use Gtk2 -init;

my $screen = Gtk2::Gdk::Screen->get_default;
my $window_width = $screen->get_width * 0.9;
my $window_height = $screen->get_height * 0.8;
$window_width = 1100 if $window_width > 1100;
$window_height = 900 if $window_height > 900;

use File::Basename;
use File::Spec;
use Parse::Win32Registry 0.51 qw( make_multiple_subtree_iterator
                                  make_multiple_subkey_iterator
                                  make_multiple_value_iterator
                                  compare_multiple_keys
                                  compare_multiple_values
                                  hexdump );

binmode(STDOUT, ':utf8');

my $script_name = basename $0;

### REGISTRY FILE STORE

use constant {
    REGCOL_FILENAME => 0,
    REGCOL_LOCATION => 1,
    REGCOL_TIMESTAMP => 2,
    REGCOL_REGISTRY => 3,
};

my $file_store = Gtk2::ListStore->new(
    'Glib::String', 'Glib::String', 'Glib::String', 'Glib::Scalar',
);

### TREE STORE

use constant {
    TREECOL_NAME => 0,
    TREECOL_CHANGES => 1,
    TREECOL_ITEMS => 2,
    TREECOL_ICON => 3,
    TREECOL_COLOR => 4,
};

my $tree_store = Gtk2::TreeStore->new(
    'Glib::String', 'Glib::Scalar', 'Glib::Scalar', 'Glib::String',
    'Glib::String',
);

my $tree_view = Gtk2::TreeView->new($tree_store);

my $icon_cell = Gtk2::CellRendererPixbuf->new;
my $name_cell = Gtk2::CellRendererText->new;
my $tree_column0 = Gtk2::TreeViewColumn->new;
$tree_column0->set_title('Name');
$tree_column0->pack_start($icon_cell, FALSE);
$tree_column0->pack_start($name_cell, TRUE);
$tree_column0->set_attributes($icon_cell,
    'stock-id', TREECOL_ICON);
$tree_column0->set_attributes($name_cell,
    'text', TREECOL_NAME,
    'foreground', TREECOL_COLOR);
$tree_view->append_column($tree_column0);
$tree_column0->set_resizable(TRUE);

$tree_view->set_rules_hint(TRUE);

# row-expanded when row is expanded (e.g. after user clicks on arrow)
$tree_view->signal_connect('row-expanded' => \&expand_row);
$tree_view->signal_connect('row-collapsed' => \&collapse_row);
# row-activated when user double clicks on row
$tree_view->signal_connect('row-activated' => \&activate_row);

my $tree_selection = $tree_view->get_selection;
$tree_selection->set_mode('browse');
$tree_selection->signal_connect('changed' => \&tree_item_selected);

my $scrolled_tree_view = Gtk2::ScrolledWindow->new;
$scrolled_tree_view->set_policy('automatic', 'automatic');
$scrolled_tree_view->set_shadow_type('in');
$scrolled_tree_view->add($tree_view);

### LIST STORE

use constant {
    LISTCOL_FILENUM => 0,
    LISTCOL_FILENAME => 1,
    LISTCOL_CHANGE => 2,
    LISTCOL_ITEM_STRING => 3,
    LISTCOL_ITEM => 4,
    LISTCOL_ICON => 5,
};

my $list_store = Gtk2::ListStore->new(
    'Glib::String', 'Glib::String', 'Glib::String', 'Glib::String',
    'Glib::Scalar', 'Glib::String',
);

my $list_view = Gtk2::TreeView->new($list_store);

my $list_cell0 = Gtk2::CellRendererText->new;
my $list_column0 = Gtk2::TreeViewColumn->new_with_attributes(
    '', $list_cell0,
    'text', LISTCOL_FILENUM);
$list_view->append_column($list_column0);

my $list_cell1 = Gtk2::CellRendererText->new;
my $list_column1 = Gtk2::TreeViewColumn->new_with_attributes(
    'Filename', $list_cell1,
    'text', LISTCOL_FILENAME);
$list_view->append_column($list_column1);
$list_column1->set_resizable(TRUE);
$list_column1->set_min_width(120);
$list_cell1->set('ellipsize', 'start');

my $list_cell2 = Gtk2::CellRendererText->new;
my $list_column2 = Gtk2::TreeViewColumn->new_with_attributes(
    'Change', $list_cell2,
    'text', LISTCOL_CHANGE);
$list_view->append_column($list_column2);
$list_column2->set_resizable(TRUE);

my $list_icon_cell = Gtk2::CellRendererPixbuf->new;
my $list_item_cell = Gtk2::CellRendererText->new;
my $list_column3 = Gtk2::TreeViewColumn->new;
$list_column3->pack_start($list_icon_cell, FALSE);
$list_column3->pack_start($list_item_cell, TRUE);
$list_column3->set_attributes($list_icon_cell,
    'stock-id', LISTCOL_ICON);
$list_column3->set_attributes($list_item_cell,
    'text', LISTCOL_ITEM_STRING);
$list_view->append_column($list_column3);
$list_column3->set_resizable(TRUE);
$list_item_cell->set('ellipsize', 'end');

$list_view->set_rules_hint(TRUE);

my $list_selection = $list_view->get_selection;
$list_selection->set_mode('browse');
$list_selection->signal_connect('changed' => \&list_item_selected);

my $scrolled_list_view = Gtk2::ScrolledWindow->new;
$scrolled_list_view->set_policy('automatic', 'automatic');
$scrolled_list_view->set_shadow_type('in');
$scrolled_list_view->add($list_view);

### TEXT VIEW

my $text_view = Gtk2::TextView->new;
$text_view->set_editable(FALSE);
$text_view->modify_font(Gtk2::Pango::FontDescription->from_string('monospace'));

my $text_buffer = $text_view->get_buffer;

my $scrolled_text_view = Gtk2::ScrolledWindow->new;
$scrolled_text_view->set_policy('automatic', 'automatic');
$scrolled_text_view->set_shadow_type('in');
$scrolled_text_view->add($text_view);

### VPANED

my $vpaned2 = Gtk2::VPaned->new;
$vpaned2->pack1($scrolled_list_view, FALSE, FALSE);
$vpaned2->pack2($scrolled_text_view, FALSE, FALSE);

### VPANED

my $vpaned1 = Gtk2::VPaned->new;
$vpaned1->pack1($scrolled_tree_view, FALSE, FALSE);
$vpaned1->pack2($vpaned2, FALSE, FALSE);

### UIMANAGER

my $uimanager = Gtk2::UIManager->new;

my @actions = (
    # name, stock id, label
    ['FileMenu', undef, '_File'],
    ['SearchMenu', undef, '_Search'],
    ['BookmarksMenu', undef, '_Bookmarks'],
    ['ViewMenu', undef, '_View'],
    ['HelpMenu', undef, '_Help'],
    # name, stock-id, label, accelerator, tooltip, callback
    ['Open', 'gtk-open', '_Open Files', '<control>O', undef, \&open_files],
    ['Close', 'gtk-close', '_Close Files', '<control>W', undef, \&close_files],
    ['Quit', 'gtk-quit', '_Quit', '<control>Q', undef, \&quit],
    ['Find', 'gtk-find', '_Find', '<control>F', undef, \&find],
    ['FindNext', undef, 'Find Next', '<control>G', undef, \&find_next],
    ['FindNext2', undef, 'Find Next', 'F3', undef, \&find_next],
    ['FindChange', 'gtk-find', 'Find _Change', '<control>N', undef, \&find_change],
    ['FindNextChange', undef, 'Find Next Change', '<control>M', undef, \&find_next_change],
    ['AddBookmark', 'gtk-add', '_Add Bookmark', '<control>D', undef, \&add_bookmark],
    ['EditBookmarks', undef, '_Edit Bookmarks', '<control>B', undef, \&edit_bookmarks],
    ['About', 'gtk-about', '_About', undef, undef, \&about],
);

my $action_group = Gtk2::ActionGroup->new('actions');
$action_group->add_actions(\@actions, undef);

my @toggle_actions = (
    # name, stock id, label, accelerator, tooltip, callback, active
    ['ShowToolbar', undef, 'Show _Toolbar', '<control>T', undef, \&toggle_toolbar, TRUE],
    ['ShowDetail', 'gtk-edit', 'Show _Detail', '<control>X', undef, \&toggle_item_detail, TRUE],
);
$action_group->add_toggle_actions(\@toggle_actions, undef);

my $action_group2 = Gtk2::ActionGroup->new('actions2'); # bookmarks
my $bookmarks_merge_id = $uimanager->new_merge_id;
my $action_name = 1; # unique action name

$uimanager->insert_action_group($action_group, 0);
$uimanager->insert_action_group($action_group2, 1);

my $ui_info = <<END_OF_UI;
<ui>
    <menubar name='MenuBar'>
        <menu action='FileMenu'>
            <menuitem action='Open'/>
            <menuitem action='Close'/>
            <separator/>
            <menuitem action='Quit'/>
        </menu>
        <menu action='SearchMenu'>
            <menuitem action='Find'/>
            <menuitem action='FindNext'/>
            <separator/>
            <menuitem action='FindChange'/>
            <menuitem action='FindNextChange'/>
        </menu>
        <menu action='BookmarksMenu'>
            <menuitem action='AddBookmark'/>
            <menuitem action='EditBookmarks'/>
            <separator/>
        </menu>
        <menu action='ViewMenu'>
            <menuitem action='ShowToolbar'/>
            <menuitem action='ShowDetail'/>
            <separator/>
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
        <toolitem action='FindChange'/>
        <separator/>
        <toolitem action='Quit'/>
    </toolbar>
    <accelerator action='FindNext2'/>
</ui>
END_OF_UI

$uimanager->add_ui_from_string($ui_info);

my $menubar = $uimanager->get_widget('/MenuBar');
my $toolbar = $uimanager->get_widget('/ToolBar');
my $bookmarks_menu = $uimanager->get_widget('/MenuBar/BookmarksMenu')->get_submenu;

### STATUSBAR

my $statusbar = Gtk2::Statusbar->new;

### VBOX

my $main_vbox = Gtk2::VBox->new(FALSE, 0);
$main_vbox->pack_start($menubar, FALSE, FALSE, 0);
$main_vbox->pack_start($toolbar, FALSE, FALSE, 0);
$main_vbox->pack_start($vpaned1, TRUE, TRUE, 0);
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

###############################################################################

sub build_open_files_dialog {
    my $file_view = Gtk2::TreeView->new($file_store);
    $file_view->set_reorderable(TRUE);

    my $file_column0 = Gtk2::TreeViewColumn->new_with_attributes(
        'Filename', Gtk2::CellRendererText->new,
        'text', REGCOL_FILENAME);
    $file_view->append_column($file_column0);
    $file_column0->set_resizable(FALSE);

    my $file_column1 = Gtk2::TreeViewColumn->new_with_attributes(
        'Embedded Filename', Gtk2::CellRendererText->new,
        'text', REGCOL_LOCATION);
    $file_view->append_column($file_column1);
    $file_column0->set_resizable(FALSE);

    my $file_column2 = Gtk2::TreeViewColumn->new_with_attributes(
        'Embedded Timestamp', Gtk2::CellRendererText->new,
        'text', REGCOL_TIMESTAMP);
    $file_view->append_column($file_column2);
    $file_column0->set_resizable(FALSE);

    my $scrolled_file_view = Gtk2::ScrolledWindow->new;
    $scrolled_file_view->set_policy('automatic', 'automatic');
    $scrolled_file_view->set_shadow_type('in');
    $scrolled_file_view->add($file_view);

    my $selection = $file_view->get_selection;
    $selection->set_mode('multiple');

    my $dialog = Gtk2::Dialog->new('Open Files', $window, 'modal',
        'gtk-clear' => 70,
        'gtk-add' => 60,
        'gtk-remove' => 50,
        'gtk-ok' => 'ok',
    );
    $dialog->set_size_request($window_width * 0.8, $window_height * 0.8);
    $dialog->vbox->add($scrolled_file_view);
    $dialog->set_default_response('ok');

    $dialog->signal_connect(delete_event => sub {
        $dialog->hide;
        return TRUE;
    });
    $dialog->signal_connect(response => sub {
        my ($dialog, $response) = @_;
        if ($response eq '70') {
            $file_store->clear;
        }
        elsif ($response eq '60') {
            my @filenames = choose_files();
            # Add filename to store
            foreach my $filename (@filenames) {
                my ($name, $path) = fileparse($filename);
                if (my $registry = Parse::Win32Registry->new($filename)) {
                    if (my $root_key = $registry->get_root_key) {
                        add_registry_file($filename);
                    }
                }
                else {
                    show_message('error', "'$name' is not a registry file.");
                }
            }
        }
        elsif ($response eq '50') {
            my $selection = $file_view->get_selection;
            my @paths = $selection->get_selected_rows;
            my @iters = map { $file_store->get_iter($_) } @paths;
            foreach my $iter (@iters) {
                $file_store->remove($iter);
            }
        }
        elsif ($response eq 'ok') {
            $dialog->hide;
            compare_files();
        }
        else {
            $dialog->hide;
        }
    });

    return $dialog;
}

my $open_files_dialog = build_open_files_dialog;

### BOOKMARKS STORE

use constant {
    BMCOL_NAME => 0,
    BMCOL_LOCATION => 1,
    BMCOL_ICON => 2,
};

my $bookmark_store = Gtk2::ListStore->new(
    'Glib::String', 'Glib::Scalar', 'Glib::String',
);

sub build_bookmarks_dialog {
    my $bookmark_view = Gtk2::TreeView->new($bookmark_store);
    $bookmark_view->set_reorderable(TRUE);

    my $bookmark_icon_cell = Gtk2::CellRendererPixbuf->new;
    my $bookmark_name_cell = Gtk2::CellRendererText->new;
    my $bookmark_column0 = Gtk2::TreeViewColumn->new;
    $bookmark_column0->set_title('Bookmark');
    $bookmark_column0->pack_start($bookmark_icon_cell, FALSE);
    $bookmark_column0->pack_start($bookmark_name_cell, TRUE);
    $bookmark_column0->set_attributes($bookmark_icon_cell,
        'stock-id', BMCOL_ICON);
    $bookmark_column0->set_attributes($bookmark_name_cell,
        'text', BMCOL_NAME);
    $bookmark_column0->set_resizable(TRUE);
    $bookmark_view->append_column($bookmark_column0);

    my $bookmark_location_cell = Gtk2::CellRendererText->new;
    my $bookmark_column1 = $bookmark_view->insert_column_with_data_func(
        1, 'Location', $bookmark_location_cell,
        sub {
            my ($column, $cell, $model, $iter, $num) = @_;
            my $location = $model->get($iter, BMCOL_LOCATION);
            if (defined $location) {
                my ($subkey_path, $value_name) = @$location;
                my $string = $subkey_path;
                if (defined $value_name) {
                    $value_name = '(Default)' if $value_name eq '';
                    $string .= ", $value_name";
                }
                $cell->set('text', $string);
            }
            else {
                $cell->set('text', '?');
            }
        },
    );
    $bookmark_location_cell->set('ellipsize', 'end');

    my $scrolled_bookmark_view = Gtk2::ScrolledWindow->new;
    $scrolled_bookmark_view->set_policy('automatic', 'automatic');
    $scrolled_bookmark_view->set_shadow_type('in');
    $scrolled_bookmark_view->add($bookmark_view);

    my $label = Gtk2::Label->new;
    $label->set_markup('<i>Drag bookmarks to reorder them</i>');

    my $dialog = Gtk2::Dialog->new('Edit Bookmarks', $window, 'modal',
        'gtk-remove' => 50,
        'gtk-ok' => 'ok',
    );
    $dialog->resize($window_width * 0.8, $window_height * 0.8);
    $dialog->vbox->pack_start($scrolled_bookmark_view, TRUE, TRUE, 0);
    $dialog->vbox->pack_start($label, FALSE, FALSE, 5);
    $dialog->set_default_response('ok');

    $dialog->signal_connect(delete_event => sub {
        $dialog->hide;
        return TRUE;
    });
    $dialog->signal_connect(response => sub {
        my ($dialog, $response) = @_;
        if ($response eq '50') {
            # Remove selected bookmark
            my $selection = $bookmark_view->get_selection;
            my $iter = $selection->get_selected;
            if (defined $iter) {
                $bookmark_store->remove($iter);
            }
        }
        else {
            # Before exiting, move menuitems into current bookmark order
            $uimanager->remove_ui($bookmarks_merge_id);
            $uimanager->ensure_update;
            foreach my $action ($action_group2->list_actions) {
                $action_group2->remove_action($action);
            }
            $action_name = 1;
            my $iter = $bookmark_store->get_iter_first;
            while (defined $iter) {
                my $bookmark_name = $bookmark_store->get($iter, BMCOL_NAME);
                my $location = $bookmark_store->get($iter, BMCOL_LOCATION);
                my $icon = $bookmark_store->get($iter, BMCOL_ICON);
                my $display_name = $bookmark_name;
                $display_name =~ s/_/__/g;
                $action_group2->add_actions([
                    [$action_name, $icon, $display_name, undef, undef, \&go_to_bookmark],
                ], $location);
                $uimanager->add_ui($bookmarks_merge_id, '/MenuBar/BookmarksMenu', $action_name, $action_name, 'menuitem', FALSE);
                $action_name++;
                $iter = $bookmark_store->iter_next($iter);
            }
            $dialog->hide;
        }
    });

    return $dialog;
}

my $bookmarks_dialog = build_bookmarks_dialog;

######################## GLOBAL SETUP

my @filenames = ();
my @root_keys = ();

my $last_dir;

my $search_keys = TRUE;
my $search_values = TRUE;
my $find_param = '';
my $find_iter;
my $change_iter;

if (@ARGV) {
    while (my $filename = shift) {
        push @filenames, $filename if -r $filename;
    }
}

@filenames = map { File::Spec->rel2abs($_) } @filenames;
foreach my $filename (@filenames) {
    if (my $registry = Parse::Win32Registry->new($filename)) {
        if (my $root_key = $registry->get_root_key) {
            add_registry_file($filename);
        }
    }
}
if (@filenames > 0) {
    compare_files();
}

Gtk2->main;

###############################################################################

sub expand_row {
    my ($view, $iter, $path) = @_;
    my $model = $view->get_model;

    # check that this is a key
    my $icon = $model->get($iter, TREECOL_ICON);
    if ($icon eq 'gtk-file') {
        return;
    }

    my $items = $model->get($iter, TREECOL_ITEMS);
    my $first_child_iter = $model->iter_nth_child($iter, 0);
    # add children if not already present
    if (!defined $model->get($first_child_iter, 0)) {
        add_children($items, $model, $iter);
        $model->remove($first_child_iter);
    }
}

sub collapse_row {
    my ($view, $iter, $path) = @_;
}

sub activate_row {
    my ($view, $path, $column) = @_;
    if ($view->row_expanded($path)) {
        $view->collapse_row($path);
    }
    else {
        $view->expand_row($path, FALSE);
    }
}

sub toggle_item_detail {
    my ($toggle_action) = @_;
    if ($toggle_action->get_active) {
        $scrolled_text_view->show;
    }
    else {
        $scrolled_text_view->hide;
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

sub tree_item_selected {
    my ($tree_selection) = @_;

    my ($model, $iter) = $tree_selection->get_selected;
    if (!defined $model || !defined $iter) {
        return;
    }

    my $name = $model->get($iter, TREECOL_NAME);
    my $changes = $model->get($iter, TREECOL_CHANGES);
    my $items = $model->get($iter, TREECOL_ITEMS);
    my $icon = $model->get($iter, TREECOL_ICON);

    $list_store->clear;
    $text_buffer->set_text('');

    my $batch_size = @root_keys;

    my $any_item;

    if (defined $changes) {
        for (my $num = 0; $num < $batch_size; $num++) {
            my $iter = $list_store->append;
            $list_store->set($iter,
                LISTCOL_FILENUM, "[$num]",
                LISTCOL_FILENAME, $filenames[$num],
                LISTCOL_CHANGE, $changes->[$num]);
            my $item = $items->[$num];
            if (defined $item) {
                my $item_as_string = $item->as_string;
                $item_as_string = substr($item_as_string, 0, 500);
                $list_store->set($iter,
                    LISTCOL_ITEM_STRING, $item_as_string,
                    LISTCOL_ITEM, $item,
                    LISTCOL_ICON, $icon);
                $any_item = $item;
            }
        }
    }
    else {
        my $iter = $list_store->append;
        $list_store->set($iter,
            LISTCOL_FILENUM, "[*]",
            LISTCOL_FILENAME, "", # ALL FILES
            LISTCOL_CHANGE, "");

        $any_item = (grep { defined } @$items)[0];
        my $any_item_as_string = $any_item->as_string;
        $any_item_as_string = substr($any_item_as_string, 0, 500);
        $list_store->set($iter,
            LISTCOL_ITEM_STRING, $any_item_as_string,
            LISTCOL_ITEM, $any_item,
            LISTCOL_ICON, $icon);
    }

    if ($icon eq 'gtk-file') {
        my $name = $any_item->get_name;
        $name = "(Default)" if $name eq '';
        my $type_as_string = $any_item->get_type_as_string;
        $statusbar->pop(0);
        $statusbar->push(0, "$name ($type_as_string)");
    }
    elsif ($icon eq 'gtk-directory') {
        $statusbar->pop(0);
        $statusbar->push(0, $any_item->get_path);
    }
}

sub list_item_selected {
    my ($list_selection) = @_;

    my ($model, $iter) = $list_selection->get_selected;
    if (!defined $model || !defined $iter) {
        return;
    }

    my $item = $model->get($iter, LISTCOL_ITEM);
    my $icon = $model->get($iter, LISTCOL_ICON);
    # there will be no item/icon for deleted items

    my $str = '';
    if (defined $item) {
        if ($icon eq 'gtk-file') { # Item is a Value
            $str .= hexdump($item->get_raw_data);
        }
        elsif ($icon eq 'gtk-directory') { # Item is a Key
            my $security = $item->get_security;
            if (defined $security) {
                my $sd = $security->get_security_descriptor;
                $str .= $sd->as_stanza;
            }
        }
    }
    $text_buffer->set_text($str);
}

sub compare_files {
    close_files();

    # Set up global variables: @filenames, @root_keys
    @filenames = ();
    @root_keys = ();
    my $iter = $file_store->get_iter_first;
    while (defined $iter) {
        my $filename = $file_store->get($iter, REGCOL_FILENAME);
        push @filenames, $filename;
        my $registry = $file_store->get($iter, REGCOL_REGISTRY);
        push @root_keys, $registry->get_root_key;
        $iter = $file_store->iter_next($iter);
    }

    my $batch_size = @root_keys;
    if ($batch_size < 2) {
        show_message('error', 'You need at least two registry files!');
        return;
    }

    # Create columns with a custom function to display changes
    for (my $num = 0; $num < $batch_size; $num++) {
        $tree_view->insert_column_with_data_func(
            $num + 1,
            "[$num]",
            Gtk2::CellRendererText->new,
            sub {
                my ($column, $cell, $model, $iter, $num) = @_;
                my $changes = $model->get($iter, TREECOL_CHANGES);
                my $color = $model->get($iter, TREECOL_COLOR);
                if (defined $changes) {
                    my $diff = substr($changes->[$num], 0, 1);
                    $cell->set('text', $diff || "\x{00bb}");
                    $cell->set('foreground', $color);
                }
                else {
                    $cell->set('text', "\x{00b7}");
                    $cell->set('foreground', $color);
                }
            },
            $num, # additional data is passed to callback
        );
    }

    add_root(\@root_keys, $tree_store, undef);
}

sub add_root {
    my ($items, $model, $parent_iter) = @_;

    my @root_keys = @$items;
    my $batch_size = @root_keys;

    my $any_root_key = (grep { defined } @root_keys)[0];

    my @changes = compare_multiple_keys(@root_keys);
    my $num_changes = grep { $_ } @changes;

    my $iter = $model->append($parent_iter);
    if ($num_changes > 0) {
        $model->set($iter,
            TREECOL_NAME, $any_root_key->get_name,
            TREECOL_CHANGES, \@changes,
            TREECOL_ITEMS, \@root_keys,
            TREECOL_ICON, 'gtk-directory',
            TREECOL_COLOR, 'black');
    }
    else {
        $model->set($iter,
            TREECOL_NAME, $any_root_key->get_name,
            #TREECOL_CHANGES, \@changes,
            TREECOL_ITEMS, \@root_keys,
            TREECOL_ICON, 'gtk-directory',
            TREECOL_COLOR, 'grey40');
    }
    my $dummy = $model->append($iter); # placeholder for children
}

sub add_children {
    my ($items, $model, $parent_iter) = @_;

    my @keys = @$items;
    my $batch_size = @keys;

    my $subkeys_iter = make_multiple_subkey_iterator(@keys);

    while (defined(my $subkeys = $subkeys_iter->get_next)) {
        my @changes = compare_multiple_keys(@$subkeys);
        my $num_changes = grep { $_ } @changes;
        # insert a 'blank' change for missing subkeys
        for (my $i = 0; $i < @changes; $i++) {
            if ($changes[$i] eq '' && !defined $subkeys->[$i]) {
                $changes[$i] = ' ';
            }
        }

        my $any_subkey = (grep { defined } @$subkeys)[0];

        my $iter = $model->append($parent_iter);

        if ($num_changes > 0) {
            $model->set($iter,
                TREECOL_NAME, $any_subkey->get_name,
                TREECOL_CHANGES, \@changes,
                TREECOL_ITEMS, $subkeys,
                TREECOL_ICON, 'gtk-directory',
                TREECOL_COLOR, 'black');
        }
        else {
            $model->set($iter,
                TREECOL_NAME, $any_subkey->get_name,
                #TREECOL_CHANGES, \@changes,
                TREECOL_ITEMS, $subkeys,
                TREECOL_ICON, 'gtk-directory',
                TREECOL_COLOR, 'grey40');
        }
        my $dummy = $model->append($iter); # placeholder for children
    }

    my $values_iter = make_multiple_value_iterator(@keys);

    while (defined(my $values = $values_iter->get_next)) {
        my @changes = compare_multiple_values(@$values);
        my $num_changes = grep { $_ } @changes;
        # insert a 'blank' change for missing values
        for (my $i = 0; $i < @changes; $i++) {
            if ($changes[$i] eq '' && !defined $values->[$i]) {
                $changes[$i] = " ";
            }
        }

        my $any_value = (grep { defined } @$values)[0];
        my $name = $any_value->get_name;
        $name = "(Default)" if $name eq '';

        my $iter = $model->append($parent_iter);

        if ($num_changes > 0) {
            $model->set($iter,
                TREECOL_NAME, $name,
                TREECOL_CHANGES, \@changes,
                TREECOL_ITEMS, $values,
                TREECOL_ICON, 'gtk-file',
                TREECOL_COLOR, 'black');
        }
        else {
            $model->set($iter,
                TREECOL_NAME, $name,
                #TREECOL_CHANGES, \@changes,
                TREECOL_ITEMS, $values,
                TREECOL_ICON, 'gtk-file',
                TREECOL_COLOR, 'grey40');
        }
    }
}

sub add_registry_file {
    my $filename = shift;

    my $registry = Parse::Win32Registry->new($filename);

    my $embedded_filename = $registry->get_embedded_filename;
    $embedded_filename = '' if !defined $embedded_filename;

    my $timestamp = $registry->get_timestamp;
    $timestamp = $registry->get_timestamp_as_string;

    my $iter = $file_store->append;
    $file_store->set($iter,
        REGCOL_FILENAME, $filename,
        REGCOL_LOCATION, $embedded_filename,
        REGCOL_TIMESTAMP, $timestamp,
        REGCOL_REGISTRY, $registry,
    );
}

sub choose_files {
    my $file_chooser = Gtk2::FileChooserDialog->new(
        'Select Registry File(s)',
        undef,
        'open',
        'gtk-cancel' => 'cancel',
        'gtk-ok' => 'ok',
    );
    $file_chooser->set_select_multiple(TRUE);
    if (defined $last_dir) {
        $file_chooser->set_current_folder($last_dir);
    }
    my @filenames = ();
    my $response = $file_chooser->run;
    if ($response eq 'ok') {
        @filenames = $file_chooser->get_filenames;
    }
    $last_dir = $file_chooser->get_current_folder;
    $file_chooser->destroy;
    return @filenames;
}

sub open_files {
    $open_files_dialog->show_all;
}

sub close_files {
    @root_keys = ();
    @filenames = ();

    $find_param = '';
    $find_iter = undef;
    $change_iter = undef;

    $tree_store->clear;
    $list_store->clear;
    $text_buffer->set_text('');
    $statusbar->pop(0);

    my @columns = $tree_view->get_columns;
    shift @columns;
    foreach my $column (@columns) {
        $tree_view->remove_column($column);
    }
}

sub quit {
    $window->destroy;
}

sub about {
    Gtk2->show_about_dialog(undef,
        'program-name' => $script_name,
        'version' => $Parse::Win32Registry::VERSION,
        'copyright' => 'Copyright (c) 2008,2009 James Macfarlane',
        'comments' => 'GTK2 Registry Compare for the Parse::Win32Registry module',
    );
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

sub find_matching_child_iter {
    my ($iter, $name, $icon) = @_;

    return if !defined $iter;

    my $child_iter = $tree_store->iter_nth_child($iter, 0);
    if (!defined $child_iter) {
        return;
    }

    if (!defined $tree_store->get($child_iter, 0)) {
        my $items = $tree_store->get($iter, TREECOL_ITEMS);
        add_children($items, $tree_store, $iter);
        $tree_store->remove($child_iter); # remove dummy items
        $child_iter = $tree_store->iter_nth_child($iter, 0); # refetch items
    }

    while (defined $child_iter) {
        my $child_name = $tree_store->get($child_iter, TREECOL_NAME);
        my $child_icon = $tree_store->get($child_iter, TREECOL_ICON);

        if ($child_name eq $name && $child_icon eq $icon) {
            return $child_iter; # match found
        }
        $child_iter = $tree_store->iter_next($child_iter);
    }
    return; # no match found
}

sub go_to_subkey_and_value {
    my $subkey_path = shift;
    my $value_name = shift;

    my @path_components = index($subkey_path, "\\") == -1
                        ? ($subkey_path)
                        : split(/\\/, $subkey_path, -1);

    my $iter = $tree_store->get_iter_first;
    return if !defined $iter; # no registry loaded

    while (defined(my $subkey_name = shift @path_components)) {
        my $items = $tree_store->get($iter, TREECOL_ITEMS);
        if (@$items == 0) {
            return;
        }

        $iter = find_matching_child_iter($iter, $subkey_name, 'gtk-directory');
        if (!defined $iter) {
            return; # no matching child iter
        }

        if (@path_components == 0) {
            # Look for a value if a value name has been supplied
            if (defined $value_name) {
                $iter = find_matching_child_iter($iter, $value_name, 'gtk-file');
                if (!defined $iter) {
                    return; # no matching child iter
                }
            }
            my $parent_iter = $tree_store->iter_parent($iter);
            my $parent_path = $tree_store->get_path($parent_iter);
            $tree_view->expand_to_path($parent_path);
            my $tree_path = $tree_store->get_path($iter);
#            $tree_view->expand_to_path($tree_path);
            $tree_view->scroll_to_cell($tree_path);
            $tree_view->set_cursor($tree_path);
            $window->set_focus($tree_view);
            return; # match found
        }
    }
}

sub get_search_message {
    my $message;
    if ($search_keys && $search_values) {
        $message = "Searching registry keys and values...";
    }
    elsif ($search_keys) {
        $message = "Searching registry keys...";
    }
    elsif ($search_values) {
        $message = "Searching registry values...";
    }
    return $message;
}

sub find_next {
    if (!defined $find_param || !defined $find_iter) {
        return;
    }

    my $label = Gtk2::Label->new;
    $label->set_text(get_search_message);
    my $dialog = Gtk2::Dialog->new('Find',
        $window,
        'modal',
        'gtk-cancel' => 'cancel',
    );
    $dialog->vbox->pack_start($label, TRUE, TRUE, 5);
    $dialog->set_default_response('cancel');
    $dialog->show_all;

    my $id = Glib::Idle->add(sub {
        my ($keys_ref, $values_ref) = $find_iter->get_next;

        if (!defined $keys_ref) {
            $dialog->response('ok');
            return FALSE; # stop searching
        }

        # Obtain the name and path from the first defined key
        my $any_key = (grep { defined } @$keys_ref)[0];
        my $subkey_path = (split(/\\/, $any_key->get_path, 2))[1];
        if (!defined $subkey_path) {
            return TRUE;
        }

        # Check values (if defined) for a match
        if (defined $values_ref) {
            if ($search_values) {
                my $any_value = (grep { defined } @$values_ref)[0];
                my $value_name = $any_value->get_name;
                if (index(lc $value_name, lc $find_param) >= 0) {
                    go_to_subkey_and_value($subkey_path, $value_name);
                    $dialog->response(50);
                    return FALSE; # stop searching
                }
            }
            return TRUE; # continue searching
        }

        # Check keys for a match
        if ($search_keys) {
            my $key_name = $any_key->get_name;
            if (index(lc $key_name, lc $find_param) >= 0) {
                go_to_subkey_and_value($subkey_path);
                $dialog->response(50);
                return FALSE; # stop searching
            }
        }
        return TRUE; # continue searching
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
    return if @root_keys == 0;

    my $entry = Gtk2::Entry->new;
    $entry->set_text($find_param);
    $entry->set_activates_default(TRUE);
    my $check1 = Gtk2::CheckButton->new('Search _Keys');
    $check1->set_active($search_keys);
    my $check2 = Gtk2::CheckButton->new('Search _Values');
    $check2->set_active($search_values);
    $check1->signal_connect(toggled => sub {
        if (!$check1->get_active && !$check2->get_active) {
            $check2->set_active(TRUE);
        }
    });
    $check2->signal_connect(toggled => sub {
        if (!$check1->get_active && !$check2->get_active) {
            $check1->set_active(TRUE);
        }
    });
    my $dialog = Gtk2::Dialog->new('Find',
        $window,
        'modal',
        'gtk-cancel' => 'cancel',
        'gtk-ok' => 'ok',
    );
    $dialog->vbox->pack_start($entry, TRUE, TRUE, 0);
    $dialog->vbox->pack_start($check1, TRUE, TRUE, 0);
    $dialog->vbox->pack_start($check2, TRUE, TRUE, 0);
    $dialog->set_default_response('ok');
    $dialog->show_all;

    my $response = $dialog->run;
    $dialog->destroy;

    if ($response eq 'ok' && @root_keys > 0) {
        $search_keys = $check1->get_active;
        $search_values = $check2->get_active;
        $find_param = $entry->get_text;
        if ($find_param ne '') {
            $find_iter = make_multiple_subtree_iterator(@root_keys);
            find_next;
        }
    }
}

sub find_next_change {
    if (!defined $change_iter) {
        return;
    }

    my $label = Gtk2::Label->new;
    $label->set_text(get_search_message);
    my $dialog = Gtk2::Dialog->new('Find Change',
        $window,
        'modal',
        'gtk-cancel' => 'cancel',
    );
    $dialog->vbox->pack_start($label, TRUE, TRUE, 5);
    $dialog->set_default_response('cancel');
    $dialog->show_all;

    my $id = Glib::Idle->add(sub {
        my ($keys_ref, $values_ref) = $change_iter->get_next;

        if (!defined $keys_ref) {
            $dialog->response('ok');
            return FALSE; # stop searching
        }

        # Obtain the name and path from the first defined key
        my $any_key = (grep { defined } @$keys_ref)[0];
        my $subkey_path = (split(/\\/, $any_key->get_path, 2))[1];
        if (!defined $subkey_path) {
            return TRUE;
        }

        # Check values (if defined) for changes
        if (defined $values_ref) {
            if ($search_values) {
                my $any_value = (grep { defined } @$values_ref)[0];
                my $value_name = $any_value->get_name;
                my @changes = compare_multiple_values(@$values_ref);
                my $num_changes = grep { $_ } @changes;
                if ($num_changes > 0) {
                    go_to_subkey_and_value($subkey_path, $value_name);
                    $dialog->response(50);
                    return FALSE; # stop searching
                }
            }
            return TRUE; # continue searching
        }

        if ($search_keys) {
            my $key_name = $any_key->get_name;
            my @changes = compare_multiple_keys(@$keys_ref);
            my $num_changes = grep { $_ } @changes;
            if ($num_changes > 0) {
                go_to_subkey_and_value($subkey_path);
                $dialog->response(50);
                return FALSE; # stop searching
            }
        }
        return TRUE; # continue searching
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

sub find_change {
    return if @root_keys == 0;

    my @start_keys = @root_keys; # default to root keys

    # Make the start keys those nearest the currently selected item
    my ($model, $iter) = $tree_selection->get_selected;
    if (defined $model && defined $iter) {
        my $icon = $model->get($iter, TREECOL_ICON);
        if ($icon eq 'gtk-directory') {
            # Item is a key, so start here
            my $items = $model->get($iter, TREECOL_ITEMS);
            @start_keys = @$items;
        }
        else {
            # Item is a value, so find parent key
            $iter = $model->iter_parent($iter);
            if (!defined $iter) {
                return;
            }
            my $items = $model->get($iter, TREECOL_ITEMS);
            @start_keys = @$items;
        }
    }

    my $start_key = (grep { defined } @start_keys)[0];
    my $key_path = $start_key->get_path;

    my $label = Gtk2::Label->new;
    $label->set_markup("Find changes starting from\n<b>$key_path</b>?");
    my $check1 = Gtk2::CheckButton->new('Search _Keys');
    $check1->set_active($search_keys);
    my $check2 = Gtk2::CheckButton->new('Search _Values');
    $check2->set_active($search_values);
    $check1->signal_connect(toggled => sub {
        if (!$check1->get_active && !$check2->get_active) {
            $check2->set_active(TRUE);
        }
    });
    $check2->signal_connect(toggled => sub {
        if (!$check1->get_active && !$check2->get_active) {
            $check1->set_active(TRUE);
        }
    });
    my $dialog = Gtk2::Dialog->new('Find Change',
        $window,
        'modal',
        'gtk-cancel' => 'cancel',
        'gtk-ok' => 'ok',
    );
    $dialog->vbox->pack_start($label, TRUE, TRUE, 5);
    $dialog->vbox->pack_start($check1, TRUE, TRUE, 0);
    $dialog->vbox->pack_start($check2, TRUE, TRUE, 0);
    $dialog->set_default_response('ok');
    $dialog->show_all;

    my $response = $dialog->run;
    $dialog->destroy;

    if ($response eq 'ok') {
        $search_keys = $check1->get_active;
        $search_values = $check2->get_active;
        $change_iter = make_multiple_subtree_iterator(@start_keys);
        $change_iter->get_next;
        find_next_change;
    }
}

sub get_location {
    my @start_keys;
    my @start_values;
    my ($keys_ref, $values_ref);
    my ($model, $iter) = $tree_selection->get_selected;
    if (defined $model && defined $iter) {
        my $icon = $model->get($iter, TREECOL_ICON);
        if ($icon eq 'gtk-directory') {
            # Item is a key
            $keys_ref = $model->get($iter, TREECOL_ITEMS);
        }
        else {
            # Item is a value
            $values_ref = $model->get($iter, TREECOL_ITEMS);

            # Find parent key
            $iter = $model->iter_parent($iter);
            return if !defined $iter;

            $keys_ref = $model->get($iter, TREECOL_ITEMS);
        }
        return ($keys_ref, $values_ref);
    }
    else {
        return ($keys_ref, $values_ref);
    }
}

sub add_bookmark {
    my ($keys_ref, $values_ref) = get_location;
    if (defined $keys_ref) {
        my $any_key = (grep { defined } @$keys_ref)[0];
        my $key_path = $any_key->get_path;
        my $key_name = $any_key->get_name;

        # Remove root key name to get subkey path
        my $subkey_path = (split(/\\/, $key_path, 2))[1];
        return if !defined $subkey_path;

        my $bookmark_name;
        my $location;
        my $icon;
        if (defined $values_ref) {
            my $any_value = (grep { defined } @$values_ref)[0];
            my $value_name = $any_value->get_name;
            $location = [$subkey_path, $value_name];
            $value_name = '(Default)' if $value_name eq '';
            $bookmark_name = "$value_name [$key_name]";
            $icon = 'gtk-file';
        }
        else {
            $bookmark_name = $key_name;
            $location = [$subkey_path];
            $icon = 'gtk-directory';
        }
        my $display_name = $bookmark_name;
        $display_name =~ s/_/__/g;
        $action_group2->add_actions([
            [$action_name, $icon, $display_name, undef, undef, \&go_to_bookmark],
        ], $location);
        $uimanager->add_ui($bookmarks_merge_id, '/MenuBar/BookmarksMenu', $action_name, $action_name, 'menuitem', FALSE);
        $action_name++;
        if (my $iter = $bookmark_store->append) {
            $bookmark_store->set($iter,
                BMCOL_NAME, $bookmark_name,
                BMCOL_LOCATION, $location,
                BMCOL_ICON, $icon,
            );
        }
    }
}

sub edit_bookmarks {
    $bookmarks_dialog->show_all;
}

sub go_to_bookmark {
    my ($menuitem, $location) = @_;
    my ($subkey_path, $value_name) = @$location;
    go_to_subkey_and_value($subkey_path, $value_name);
}
