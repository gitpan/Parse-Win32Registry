#!/usr/bin/perl
use strict;
use warnings;

binmode(STDOUT, ':utf8');

use Glib ':constants';
use Gtk2 -init;

use File::Basename;
use Getopt::Long;
use Parse::Win32Registry qw(hexdump :REG_);

Getopt::Long::Configure('bundling');

GetOptions('debug|d' => \my $debug_mode);

my $script_name = basename $0;

# Widgets:
# window
#   main_vbox
#     menu
#     hpane
#       tree_view
#       vbox
#         entry
#         vpane
#           list_view
#           text_view

### LIST VIEW

my $list_store = Gtk2::ListStore->new(
    'Glib::String', 'Glib::String', 'Glib::String', 'Glib::Scalar',
    );

my $list_view = Gtk2::TreeView->new($list_store);

my $list_column1 = Gtk2::TreeViewColumn->new_with_attributes(
    'Name', Gtk2::CellRendererText->new, text => 0);
$list_view->append_column($list_column1);
$list_column1->set_resizable(TRUE);

my $list_column2 = Gtk2::TreeViewColumn->new_with_attributes(
    'Type', Gtk2::CellRendererText->new, text => 1);
$list_view->append_column($list_column2);
$list_column2->set_resizable(TRUE);

my $list_column3 = Gtk2::TreeViewColumn->new_with_attributes(
    'Data', Gtk2::CellRendererText->new, text => 2);
$list_view->append_column($list_column3);
$list_column3->set_resizable(TRUE);

my $list_selection = $list_view->get_selection;
$list_selection->set_mode('browse');
$list_selection->signal_connect('changed' => \&list_selection_changed);

my $scrolled_list_view = Gtk2::ScrolledWindow->new;
$scrolled_list_view->set_policy('automatic', 'automatic');
$scrolled_list_view->set_shadow_type('in');
$scrolled_list_view->add($list_view);

### TEXT VIEW

my $text_view = Gtk2::TextView->new;
$text_view->set_editable(FALSE);
$text_view->modify_font(Gtk2::Pango::FontDescription->from_string('monospace'));

my $scrolled_text_view = Gtk2::ScrolledWindow->new;
$scrolled_text_view->set_policy('automatic', 'automatic');
$scrolled_text_view->set_shadow_type('in');
$scrolled_text_view->add($text_view);

### VPANED

my $vpane = Gtk2::VPaned->new;
$vpane->add1($scrolled_list_view);
$vpane->add2($scrolled_text_view);

### ENTRY

my $entry = Gtk2::Entry->new;

### VBOX

my $vbox = Gtk2::VBox->new;
$vbox->pack_start($entry, FALSE, FALSE, 0);
$vbox->pack_start($vpane, TRUE, TRUE, 0);

### TREE VIEW

my $tree_store = Gtk2::TreeStore->new(
    'Glib::String', 'Glib::String', 'Glib::String', 'Glib::Scalar',
    );
my $tree_view = Gtk2::TreeView->new($tree_store);

my $tree_column1 = Gtk2::TreeViewColumn->new_with_attributes(
    'Key', Gtk2::CellRendererText->new, text => 0);
$tree_view->append_column($tree_column1);
$tree_column1->set_resizable(TRUE);

my $tree_column2 = Gtk2::TreeViewColumn->new_with_attributes(
    'Time', Gtk2::CellRendererText->new, text => 1);
$tree_view->append_column($tree_column2);
$tree_column2->set_resizable(TRUE);

my $tree_column3 = Gtk2::TreeViewColumn->new_with_attributes(
    'Class', Gtk2::CellRendererText->new, text => 2);
$tree_view->append_column($tree_column3);
$tree_column3->set_resizable(TRUE);

$tree_view->signal_connect('row-expanded' => \&tree_row_expanded);
$tree_view->signal_connect('row-activated' => \&tree_row_activated);

my $tree_selection = $tree_view->get_selection;
$tree_selection->set_mode('browse');
$tree_selection->signal_connect('changed' => \&tree_selection_changed);

my $scrolled_tree_view = Gtk2::ScrolledWindow->new;
$scrolled_tree_view->set_size_request(200,300);
$scrolled_tree_view->set_policy('automatic', 'automatic');
$scrolled_tree_view->set_shadow_type('in');
$scrolled_tree_view->add($tree_view);

### HPANED

my $hpane = Gtk2::HPaned->new;
$hpane->add1($scrolled_tree_view);
$hpane->add2($vbox);

### MENU

use Gtk2::SimpleMenu;

my $menu_tree = [
    _File => {
        item_type => '<Branch>',
        children => [
            _Open => {
                item_type => '<Item>',
                callback => \&open,
                accelerator => '<ctrl>O',
            },
            _Close => {
                item_type => '<Item>',
                callback => \&close,
                accelerator => '<ctrl>W',
            },
            Separator => {
                item_type => '<Separator>',
            },
            _Quit => {
                callback => \&quit,
                accelerator => '<ctrl>Q',
            },
        ],
    },
    #_View => {
    #    item_type => '<Branch>',
    #},
    _Help => {
        item_type => '<Branch>',
        children => [
            _About => {
                callback => \&about,
            },
        ],
    },
];

my $menu = Gtk2::SimpleMenu->new(
    menu_tree => $menu_tree,
    user_data => 'main_menu',
);

### VBOX

my $main_vbox = Gtk2::VBox->new;
$main_vbox->pack_start($menu->{widget}, FALSE, FALSE, 0);
$main_vbox->pack_start($hpane, TRUE, TRUE, 0);

### WINDOW

my $window = Gtk2::Window->new;
$window->set_default_size(600,300);
$window->set_position('center');
$window->signal_connect(destroy => sub { Gtk2->main_quit });
$window->add($main_vbox);
$window->add_accel_group($menu->{accel_group});
$window->set_title($script_name);
$window->show_all;

my $filename = shift;
if (defined $filename && -r $filename) {
    load_file($filename);
}

Gtk2->main;

###############################################################################

sub list_selection_changed {
    my ($model, $iter) = $list_selection->get_selected;
    if (!defined $model || !defined $iter) {
        return;
    }
    my $name = $model->get($iter, 0);
    my $value = $model->get($iter, 3);
    my $text_buffer = $text_view->get_buffer;
    my $s = '';
    $s .= hexdump($value->get_raw_data);
    if ($debug_mode) {
        $s .= "\n" . $value->parse_info . "\n" . $value->as_hexdump;
    }
    $text_buffer->set_text($s."\n");
}

sub tree_row_activated {
    my ($view, $path, $column) = @_;
    if ($view->row_expanded($path)) {
        $view->collapse_row($path);
    }
    else {
        # rows will only be expanded if they have children
        $view->expand_row($path, FALSE);
    }
}

sub add_root {
    my ($model, $parent_iter, $key) = @_;
    my $iter = $model->append($parent_iter);
    $model->set($iter,
        0 => $key->get_name,
        1 => $key->get_timestamp ? $key->get_timestamp_as_string : "",
        2 => $key->get_class_name ? $key->get_class_name : "",
        3 => $key,
        );
    my $dummy = $model->append($iter);
}

sub add_children {
    my ($model, $parent_iter, $key) = @_;
    my @subkeys = $key->get_list_of_subkeys;
    if (@subkeys) {
        for my $subkey (@subkeys) {
            my $child_iter = $model->append($parent_iter);
            $model->set($child_iter,
                0 => $subkey->get_name,
                1 => $subkey->get_timestamp ? $subkey->get_timestamp_as_string
                                            : "",
                2 => $subkey->get_class_name ? $subkey->get_class_name
                                            : "",
                3 => $subkey,
                );
            my $dummy = $model->append($child_iter);
        }
    }
}

sub tree_row_expanded {
    my ($view, $iter, $path) = @_;
    my $model = $view->get_model;
    my $key = $model->get($iter, 3);
    my $first_child_iter = $model->iter_nth_child($iter, 0);
    if (!defined $model->get($first_child_iter, 0)) {
        add_children($model, $iter, $key);
        $model->remove($first_child_iter);
    }
}

sub tree_selection_changed {
    my ($tree_selection) = @_;
    my ($model, $iter) = $tree_selection->get_selected;
    if (!defined $model || !defined $iter) {
        return;
    }
    my $key = $model->get($iter, 3);
    $list_store->clear;
    my @values = $key->get_list_of_values;
    if (@values) {
        for my $value (@values) {
            my $name = $value->get_name;
            my $type = $value->get_type_as_string;
            my $data = $value->get_data_as_string;
            # abbreviate long data
            if (length($data) > 47) {
                $data = substr($data, 0, 47) . "...";
            }
            my $iter = $list_store->append;
            $list_store->set($iter,
                0 => $name,
                1 => $type,
                2 => $data,
                3 => $value);
        }
    }
    my $text_buffer = $text_view->get_buffer;
    my $s = '';
    if ($debug_mode) {
        $s .= $key->parse_info . "\n" . $key->as_hexdump;
    }
    $text_buffer->set_text($s);
    $entry->set_text($key->get_path);
}

sub load_file {
    my $filename = shift;
    my ($name, $path) = fileparse($filename);
    print "Loading '$name' from '$path'\n";
    $tree_store->clear;
    $list_store->clear;
    $entry->set_text('');
    if (my $registry = Parse::Win32Registry->new($filename)) {
        if (my $root_key = $registry->get_root_key) {
            add_root($tree_store, undef, $root_key);
            $window->set_title("$name - $script_name");
        }
    }
    else {
        my $dialog = Gtk2::MessageDialog->new(
            $window,
            'destroy-with-parent',
            'error',
            'ok',
            "'$name' is not a registry file.",
        );
        $dialog->run;
        $dialog->destroy;
    }
}

sub open {
    my $file_chooser = Gtk2::FileChooserDialog->new(
        'Select Registry File',
        undef,
        'open',
        'gtk-cancel' => 'cancel',
        'gtk-ok' => 'ok',
    );
    my $filename;
    my $response = $file_chooser->run;
    if ($response eq 'ok') {
        $filename = $file_chooser->get_filename;
    }
    $file_chooser->destroy;
    if ($filename) {
        load_file($filename);
    }
}

sub close {
    $tree_store->clear;
    $list_store->clear;
    $entry->set_text('');
}

sub quit {
    $window->destroy;
}

sub about {
    Gtk2->show_about_dialog(undef,
        name => $script_name,
        version => $Parse::Win32Registry::VERSION,
        copyright => 'Copyright (c) 2008 James Macfarlane',
        comments => 'GTK2 Registry Viewer for the Parse::Win32Registry module',
    );
}

