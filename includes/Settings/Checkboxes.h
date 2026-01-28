EMSCRIPTEN_KEEPALIVE
bool isUpdateChecksumChecked() {
    emscripten::val document = emscripten::val::global("document");
    emscripten::val checkbox = document.call<emscripten::val>("getElementById", std::string("updateChecksum"));
    return checkbox["checked"].as<bool>();
}

EMSCRIPTEN_KEEPALIVE
bool isRemoveCertChecked() {
    emscripten::val document = emscripten::val::global("document");
    emscripten::val checkbox = document.call<emscripten::val>("getElementById", std::string("removeCert"));
    return checkbox["checked"].as<bool>();
}

EMSCRIPTEN_KEEPALIVE
bool isKeepBindChecked() {
    emscripten::val document = emscripten::val::global("document");
    emscripten::val checkbox = document.call<emscripten::val>("getElementById", std::string("keepBind"));
    return checkbox["checked"].as<bool>();
}