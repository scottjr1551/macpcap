//
// Created by Scott Roberts on 10/8/22.
//

#ifndef MACPCAP_GUISETUP_H
#define MACPCAP_GUISETUP_H

#include <gtkmm.h>

class Guisetup : public Gtk::Window {
public:
    Guisetup();

    virtual ~Guisetup();

private:
    // Signal handlers:
    void on_button_quit();

    void on_button_numbered(const Glib::ustring &data);

    // Child widgets:
    Gtk::Grid m_grid;
    Gtk::Button m_button_1, m_button_2, m_button_quit;
};

#endif //MACPCAP_GUISETUP_H
