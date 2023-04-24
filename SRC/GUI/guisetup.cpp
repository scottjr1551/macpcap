//
// Created by Scott Roberts on 10/8/22.
//
#include "guisetup.h"
#include <iostream>

Guisetup::Guisetup()
        : m_button_1("Open File"),
          m_button_2("PCAP Analyze"),
          m_button_quit("Quit") {
    set_title("Macpcap Analyzer");

    m_grid.set_margin(12);
    set_child(m_grid);

    m_grid.attach(m_button_1, 0, 0);
    m_grid.attach(m_button_2, 1, 0);
    m_grid.attach_next_to(m_button_quit, m_button_1, Gtk::PositionType::BOTTOM, 2, 1);

    m_button_1.signal_clicked().connect(
            sigc::bind(sigc::mem_fun(*this, &Guisetup::on_button_numbered), "button 1"));
    m_button_2.signal_clicked().connect(
            sigc::bind(sigc::mem_fun(*this, &Guisetup::on_button_numbered), "button 2"));

    m_button_quit.signal_clicked().connect(sigc::mem_fun(*this,
                                                         &Guisetup::on_button_quit));
}

Guisetup::~Guisetup() {
}

void Guisetup::on_button_quit() {
    hide();
}

void
Guisetup::on_button_numbered(const Glib::ustring &data) {
    std::cout << data << " was pressed" << std::endl;
}