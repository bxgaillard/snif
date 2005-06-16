/*
 * ---------------------------------------------------------------------------
 *
 * Snif: a packet sniffer and analyzer
 * Copyright (C) 2005 Benjamin Gaillard & Yannick Schuffenecker
 *
 * ---------------------------------------------------------------------------
 *
 *        File: main.c
 *
 * Description: Main GUI Functions
 *
 * ---------------------------------------------------------------------------
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * ---------------------------------------------------------------------------
 */


/*****************************************************************************
 *
 * Headers
 *
 */

/* Additional definitions */
#define _BSD_SOURCE

/* Standard C library */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* UNIX */
#include <unistd.h>

/* libpcap */
#include <pcap.h>

/* GTK+ */
#include <gtk/gtk.h>

/* Current module */
#include "analyze.h"
#include "describe.h"
#include "main.h"


/*****************************************************************************
 *
 * Constants and Macros
 *
 */

#ifdef __GNUC__
# define UNUSED __attribute__((__unused__))
#else /* __GNUC__ */
# define UNUSED
#endif /* !__GNUC__ */


/*****************************************************************************
 *
 * Data Types
 *
 */

/* Packet linked list */
struct packet_list {
    int            number;       /* Packet count           */
    struct packet *first, *last; /* First and last element */
};


/*****************************************************************************
 *
 * Private Variables
 *
 */

/* Set if capturing has started */
static int started = 0;

/* Packet linked list */
static struct packet_list packets;

/* Globally used GTK+ objects */
static GtkWidget    *filter_entry;
static GtkListStore *packets_list;

/* libpcap opened device */
static pcap_t *pcap_dev;

/* libpcap error buffer */
static char errbuf[PCAP_ERRBUF_SIZE];


/*****************************************************************************
 *
 * Prototypes
 *
 */

/* Packet storage */
static int  add_packet(const unsigned size, const unsigned char *const data,
		       const struct timeval *const time,
		       const enum packet_type type);
static void free_packets(void);

/* GUI functions */
static void create_window(void);
static void fill_dev_list(GtkListStore *const devlist,
			  GtkTreeSelection *const selection);
static void error_dialog(const char *const message);

/* Event handlers */
static void     packet_handler(unsigned char *const userdata UNUSED,
			       const struct pcap_pkthdr *const header,
			       const unsigned char *const data);
static gboolean event_timeout(gpointer data);
static void     event_show(GtkWidget *widget UNUSED, gpointer data UNUSED);
static gboolean event_delete(GtkWidget *widget UNUSED, GdkEvent *event UNUSED,
			     gpointer data UNUSED);
static void     event_destroy(GtkWidget *widget UNUSED, gpointer data UNUSED);
static void     event_start_stop(GtkWidget *widget, gpointer data UNUSED);
static void     event_changed(GtkTreeSelection *const selection,
			      gpointer data);


/*****************************************************************************
 *
 * Public Functions
 *
 */


/*
 * Main function.
 */
int main(int argc, char *argv[])
{
    /* Initialization */
    gtk_init (&argc, &argv);

    /* Create window and enter main loop */
    create_window();
    gtk_main();

    /* Free memory */
    free_packets();

    /* No error */
    return 0;
}

/*****************************************************************************
 *
 * Private Functions
 *
 */

/*
 * Add a packet in the memory and in the GUI.
 */
static int add_packet(const unsigned size, const unsigned char *const data,
		      const struct timeval *const time,
		      const enum packet_type type)
{
    /* Local variables */
    struct packet *p;
    char           buffer[16];

    if ((p = (struct packet *) malloc(sizeof(struct packet) + size))
	!= NULL) {
	GtkTreeIter iter;

	/* Update packet list structure */
	packets.number++;
	if (packets.first == NULL)
	    packets.first = p;
	else
	    packets.last->next = p;
	packets.last = p;

	/* Add this packet */
	p->next = NULL;
	p->time = *time;
	p->type = type;
	p->size = size;
	p->data = (const unsigned char *) (p + 1);
	memcpy((unsigned char *) p->data, data, size);

	/* Add this packet to the GUI list */
	sprintf(buffer, "%d", packets.number);
	gtk_list_store_append(packets_list, &iter);
	gtk_list_store_set(packets_list, &iter, 0, buffer,
			   1, describe_packet(p),
			   2, packets.number, 3, p, -1);

	/* No error */
	return 0;
    }

    /* Error */
    return 1;
}

/*
 * Free all packets stored in memory.
 */
static void free_packets(void)
{
    /* Local variables */
    struct packet *p, *next;

    /* Free every single stored packet */
    for (p = packets.first; p != NULL; p = next) {
	next = p->next;
	free(p);
    }

    /* Reinitialize packet list */
    packets.number = 0;
    packets.first = NULL;
}

/*
 * Create the main window all all the widgets inside it.
 */
static void create_window(void)
{
    /* Local variables */
    GtkWidget           *window, *vbox;
    GtkWidget            *options, *opt_table;
    GtkWidget            *devs_label, *devs_scroll, *devs;
    GtkListStore         *devs_list;
    GtkCellRenderer      *renderer;
    GtkTreeViewColumn    *column;
    GtkTreeSelection     *select;
    GtkWidget            *filter_label, *filter;
    GtkWidget            *start, *quit;
    GtkWidget            *vpaned;
    GtkWidget            *packets_scroll, *packets;
    GtkWidget            *desc_scroll, *desc;
    GtkTextBuffer        *desc_buffer;
    PangoFontDescription *font;

    /* Window */
    window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "Snif");
    gtk_window_set_default_size(GTK_WINDOW(window), 600, 450);
    gtk_container_set_border_width(GTK_CONTAINER(window), 4);
    g_signal_connect(G_OBJECT(window), "show",
		     G_CALLBACK(event_show), NULL);
    g_signal_connect(G_OBJECT(window), "delete-event",
		     G_CALLBACK(event_delete), NULL);
    g_signal_connect(G_OBJECT(window), "destroy",
		     G_CALLBACK(event_destroy), NULL);

    /* Vertical box */
    vbox = gtk_vbox_new(FALSE, 4);
    gtk_container_add(GTK_CONTAINER(window), vbox);

    /* Options frame */
    options = gtk_frame_new("Options");
    gtk_box_pack_start(GTK_BOX(vbox), options, FALSE, TRUE, 0);

    /* Options table */
    opt_table = gtk_table_new(4, 3, FALSE);
    gtk_container_add(GTK_CONTAINER(options), opt_table);

    /* Device label */
    devs_label = gtk_label_new("Device:");
    gtk_table_attach(GTK_TABLE(opt_table), devs_label, 0, 1, 0, 1,
		     (GtkAttachOptions) (GTK_SHRINK | GTK_FILL),
		     (GtkAttachOptions) (GTK_SHRINK | GTK_FILL), 4, 0);
    gtk_misc_set_alignment(GTK_MISC(devs_label), 0.0, 1.0);

    /* Filter label */
    filter_label = gtk_label_new("Filter (see libpcap manual):");
    gtk_table_attach(GTK_TABLE(opt_table), filter_label, 1, 4, 0, 1,
		     (GtkAttachOptions) (GTK_SHRINK | GTK_FILL),
		     (GtkAttachOptions) (GTK_SHRINK | GTK_FILL), 4, 0);
    gtk_misc_set_alignment(GTK_MISC(filter_label), 0.0, 1.0);

    /* Device list scroll */
    devs_scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(devs_scroll),
				   GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(devs_scroll),
					GTK_SHADOW_IN);
    gtk_table_attach(GTK_TABLE(opt_table), devs_scroll, 0, 1, 1, 3,
		     (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
		     (GtkAttachOptions) (GTK_EXPAND | GTK_FILL), 4, 4);

    /* Device list control */
    devs_list = gtk_list_store_new(2, G_TYPE_STRING, G_TYPE_STRING);
    devs = gtk_tree_view_new_with_model(GTK_TREE_MODEL(devs_list));
    /*gtk_tree_view_set_fixed_height_mode(GTK_TREE_VIEW(devs), TRUE);*/
    gtk_tree_view_set_headers_visible(GTK_TREE_VIEW(devs), FALSE);
    gtk_container_add(GTK_CONTAINER(devs_scroll), devs);

    /* Device list columns */
    renderer = gtk_cell_renderer_text_new();
    column = gtk_tree_view_column_new_with_attributes("Device", renderer,
						      "text", 0, NULL);
    gtk_tree_view_append_column(GTK_TREE_VIEW(devs), column);
    column = gtk_tree_view_column_new_with_attributes("Description", renderer,
						      "text", 1, NULL);
    gtk_tree_view_append_column(GTK_TREE_VIEW(devs), column);

    /* Fill device list */
    select = gtk_tree_view_get_selection(GTK_TREE_VIEW(devs));
    gtk_tree_selection_set_mode(GTK_TREE_SELECTION(select),
				GTK_SELECTION_BROWSE);
    fill_dev_list(devs_list, select);

    /* Filter entry */
    filter = gtk_entry_new();
    gtk_table_attach(GTK_TABLE(opt_table), filter, 1, 3, 1, 2,
		     (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
		     (GtkAttachOptions) GTK_SHRINK, 4, 4);
    filter_entry = filter;

    /* Start button */
    start = gtk_button_new_with_label("Start");
    gtk_table_attach(GTK_TABLE(opt_table), start, 1, 2, 2, 3,
		     (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
		     (GtkAttachOptions) GTK_SHRINK, 4, 4);
    g_signal_connect(G_OBJECT(start), "clicked",
		     G_CALLBACK(event_start_stop), devs);

    /* Quit button */
    quit = gtk_button_new_with_label("Quit");
    g_signal_connect_swapped(G_OBJECT(quit), "clicked",
			     G_CALLBACK(gtk_widget_destroy),
			     G_OBJECT(window));
    gtk_table_attach(GTK_TABLE(opt_table), quit, 2, 3, 2, 3,
		     (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
		     (GtkAttachOptions) GTK_SHRINK, 4, 4);

    /* Vertical paned */
    vpaned = gtk_vpaned_new();
    gtk_paned_set_position(GTK_PANED(vpaned), 100);
    gtk_box_pack_start(GTK_BOX(vbox), vpaned, TRUE, TRUE, 0);

    /* Packet list scroll */
    packets_scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(packets_scroll),
				   GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(packets_scroll),
					GTK_SHADOW_IN);
    gtk_paned_add1(GTK_PANED(vpaned), packets_scroll);

    /* Packet list control */
    packets_list = gtk_list_store_new(4, G_TYPE_STRING, G_TYPE_STRING,
				      G_TYPE_INT, G_TYPE_POINTER);
    packets = gtk_tree_view_new_with_model(GTK_TREE_MODEL(packets_list));
    gtk_container_add(GTK_CONTAINER(packets_scroll), packets);

    /* Packet list columns */
    column = gtk_tree_view_column_new_with_attributes("Number", renderer,
						      "text", 0, NULL);
    gtk_tree_view_append_column(GTK_TREE_VIEW(packets), column);
    column = gtk_tree_view_column_new_with_attributes("Description", renderer,
						      "text", 1, NULL);
    gtk_tree_view_append_column(GTK_TREE_VIEW(packets), column);

    /* Description scroll */
    desc_scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(desc_scroll),
				   GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(desc_scroll),
					GTK_SHADOW_IN);
    gtk_paned_add2(GTK_PANED(vpaned), desc_scroll);

    /* Description text */
    desc = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(desc), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(desc), FALSE);
    gtk_container_add(GTK_CONTAINER(desc_scroll), desc);

    /* Change text font (monospace) */
    font = pango_font_description_new();
    pango_font_description_set_family(font, "Monospace, Bitstream Vera Sans "
				      "Mono, Courier, Fixed");
    gtk_widget_modify_font(desc, font);

    /* Packet list selection change signal */
    select = gtk_tree_view_get_selection(GTK_TREE_VIEW(packets));
    desc_buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(desc));
    g_signal_connect(G_OBJECT(select), "changed",
		     G_CALLBACK(event_changed), desc_buffer);

    /* Show window */
    gtk_widget_show_all(window);
}

/*
 * Packet handler for libpcap.
 */
static void packet_handler(unsigned char *const userdata UNUSED,
			   const struct pcap_pkthdr *const header,
			   const unsigned char *const data)
{
    /* Local variables */
    enum packet_type type;

    /* Determine packet type */
    switch (pcap_datalink(pcap_dev)) {
    case DLT_RAW:
	type = PT_RAW;
	break;

    case DLT_EN10MB:
	type = PT_ETHERNET;
	break;

    case DLT_LINUX_SLL:
	type = PT_LINUX;
	break;

    default:
	type = PT_UNKNOWN;
    }

    /* Store this packet in memory if its type is knownst to us */
    if (type != PT_UNKNOWN)
	add_packet(header->caplen, data, &header->ts, type);
}

/*
 * Fill in the device list in main window.
 */
static void fill_dev_list(GtkListStore *const devlist,
			  GtkTreeSelection *const selection)
{
    /* Local variables */
    pcap_if_t  *dev, *devs;
    GtkTreeIter iter;
    char *const def_dev = pcap_lookupdev(errbuf);

    if (pcap_findalldevs(&devs, errbuf) != -1) {
	for (dev = devs; dev != NULL; dev = dev->next) {
	    /* Add device to the list */
	    gtk_list_store_append(devlist, &iter);
	    gtk_list_store_set(devlist, &iter, 0, dev->name, 1,
			       dev->description != NULL ?
			       dev->description : "", -1);

	    /* If this is the default device, select it */
	    if (strcmp(def_dev, dev->name) == 0)
		gtk_tree_selection_select_iter(selection, &iter);
	}

	/* Free memory */
	pcap_freealldevs(devs);

	/* If no default device found, select the first one */
	if (def_dev == NULL) {
	    if (gtk_tree_model_get_iter_first(GTK_TREE_MODEL(devlist), &iter))
		gtk_tree_selection_select_iter(selection, &iter);
	}
    } else
	error_dialog("Error: cannot get device list.");
}

/*
 * Display an error dialog.
 */
static void error_dialog(const char *const message)
{
    /* Create dialog */
    GtkWidget *dialog;
    dialog = gtk_message_dialog_new(NULL, GTK_DIALOG_MODAL,
				    GTK_MESSAGE_WARNING,
				    GTK_BUTTONS_CLOSE, message);

    /* Display it then destroy it */
    gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
}

/*
 * Timeout handler for GLib.
 */
static gboolean event_timeout(gpointer data)
{
    if (started) {
	/* Process captured packets */
	while (pcap_dispatch(pcap_dev, -1, packet_handler,
			     (unsigned char *) data) > 0);
	return TRUE;
    }

    /* End timeout */
    return FALSE;
}

/*
 * Event triggered when main window is displayed.
 */
static void event_show(GtkWidget *widget UNUSED, gpointer data UNUSED)
{
    /* Warn if not root */
    if (geteuid() != 0) {
	GtkWidget *dialog;
	dialog = gtk_message_dialog_new(NULL, GTK_DIALOG_MODAL,
					GTK_MESSAGE_WARNING,
					GTK_BUTTONS_OK,
					"Warning: you may need to be root to "
					"open devices for capturing.");
	gtk_dialog_run(GTK_DIALOG(dialog));
	gtk_widget_destroy(dialog);
    }
}

/*
 * Event triggered when main window is to be closed.
 */
static gboolean event_delete(GtkWidget *widget UNUSED, GdkEvent *event UNUSED,
			     gpointer data UNUSED)
{
    /* Stop capturing */
    if (started)
	pcap_close(pcap_dev);

    /* Request window destruction */
    return FALSE;
}

/*
 * Event triggered when main window gets destroyed.
 */
static void event_destroy(GtkWidget *widget UNUSED, gpointer data UNUSED)
{
    /* Stop main loop */
    gtk_main_quit();
}

/*
 * Event triggered when the start/stop button is clicked.
 */
static void event_start_stop(GtkWidget *widget, gpointer data UNUSED)
{
    if (!started) {
	/* Variables */
	GtkTreeSelection *const selection =
	    gtk_tree_view_get_selection(GTK_TREE_VIEW(data));
	GtkTreeIter             iter;
	GtkTreeModel           *model;

	/* Get list selection */
	if (gtk_tree_selection_get_selected(selection, &model, &iter)) {
	    /* Variables */
	    const char *devname;
	    char *filter;

	    /* Get filter string */
	    gtk_tree_model_get(model, &iter, 0, &devname, -1);
	    filter = strdup(gtk_entry_get_text(GTK_ENTRY(filter_entry)));

	    /* Open device for capturing */
	    if ((pcap_dev = pcap_open_live(devname, 65536, 1, 0,
					   errbuf)) != NULL) {
		/* Variables */
		static struct bpf_program program;

		/* Compile filter */
		if (pcap_compile(pcap_dev, &program, filter, 1, 0) != -1 &&
		    /* Apply filter and set non-blocking mode */
		    pcap_setfilter(pcap_dev, &program) != -1) {
		    pcap_setnonblock(pcap_dev, 1, errbuf);

		    /* Activate packet capturing timer */
		    g_timeout_add(500, event_timeout, &packets);

		    /* Update button text */
		    gtk_button_set_label(GTK_BUTTON(widget), "Stop");
		    started = 1;
		} else {
		    error_dialog("Error: cannot apply filter. Check syntax.");
		    pcap_close(pcap_dev);
		}
	    } else
		error_dialog("Error: cannot open device for capturing.");
	}
    } else {
	/* End capture */
	pcap_close(pcap_dev);

	/* Update button text */
	gtk_button_set_label(GTK_BUTTON(widget), "Start");
	started = 0;
    }
}

/*
 * Event triggered when list selection changed.
 */
static void event_changed(GtkTreeSelection *const selection, gpointer data)
{
    /* Local variables */
    GtkTextBuffer *const buffer = (GtkTextBuffer *) data;
    GtkTreeModel        *model;
    GtkTreeIter          iter;

    if (gtk_tree_selection_get_selected(selection, &model, &iter)) {
	/* Variables */
	struct packet *packet;

	/* Display packet informations */
	gtk_tree_model_get(model, &iter, 3, &packet, -1);
	analyze_packet(buffer, packet);
    } else {
	/* Variables */
	GtkTextIter iter_start, iter_end;

	/* Clear packet description */
	gtk_text_buffer_get_start_iter(buffer, &iter_start);
	gtk_text_buffer_get_end_iter(buffer, &iter_end);
	gtk_text_buffer_delete(buffer, &iter_start, &iter_end);
    }
}

/* End of file */
