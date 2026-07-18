        """Load wireless interfaces using the same logic as CLI (iw dev + iwconfig)."""
        self.interface_list.clear()

        try:
            # 1) Get interface names using your CLI helper
            interfaces = self.manager.list_interfaces()   # uses `iw dev`
            if not interfaces:
                QMessageBox.warning(
                    self, "No Interfaces",
                    "No wireless interfaces found.\n\nCheck: iw dev"
                )
                return

            items_to_add = []
            for iface in interfaces:
                mode = self.manager.get_interface_mode(iface)  # uses iwconfig
                # Normalize mode text
                if mode.lower().startswith("monitor"):
                    mode_text = "Monitor"
                elif mode.lower().startswith("managed"):
                    mode_text = "Managed"
                else:
                    mode_text = mode

                items_to_add.append((iface, mode_text))

            # 2) Populate QListWidget
            item_to_select = None
            for iface, mode in items_to_add:
                icon = "📡" if mode == "Monitor" else "🔌"
                item = QListWidgetItem(f"{icon} {iface} ({mode})")
                item.setData(Qt.ItemDataRole.UserRole, (iface, mode))
                self.interface_list.addItem(item)

                # Prefer selecting parent's current interface if present
                if self.current_interface_from_parent and iface == self.current_interface_from_parent:
                    item_to_select = item

            # If nothing selected yet, auto‑select first interface
            if not item_to_select and self.interface_list.count() > 0:
                item_to_select = self.interface_list.item(0)

            if item_to_select:
                self.interface_list.setCurrentItem(item_to_select)
                self.on_interface_selected(item_to_select)

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load interfaces:\n{e}")
