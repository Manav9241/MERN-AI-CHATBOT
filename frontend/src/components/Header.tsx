import { AppBar, Toolbar } from "@mui/material";
import React from "react";
import Logo from "./shared/logo";

const Header = () => {
  return (
    <AppBar
      sx={{ bgcolor: "transparent", position: "static", boxShadow: "none" }}
    >
      <Toolbar sx={{ display: "flex" }}>
        <Logo />
      </Toolbar>
    </AppBar>
  );
};

export default Header;
