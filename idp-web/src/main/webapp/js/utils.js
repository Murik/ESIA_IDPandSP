//////////////////////////////////////
//         Utility functions        //
//////////////////////////////////////
var COOKIE_LANG_NAME = "userSelectedLanguage";
var COOKIE_LANG_PATH = "/";

function setLanguage(lang) {
    setCookie(COOKIE_LANG_NAME, lang, COOKIE_LANG_PATH, "", "")
}

// set cookie expired by given milliseconds
function setCookie(_name,_value,  _path, _domain, _duration_in_milliseconds) {
    var _expiry = new Date( new Date().getTime() + _duration_in_milliseconds);
    _setCookie(_name, _value, _expiry.toUTCString(), _path, _domain,'secure');
}

// set cookie
function _setCookie (name, value, expires, path, domain, secure) {
    document.cookie = name + "=" + escape(value)
        + ((expires) ? "; expires=" + expires : "")
        + ((path) ? "; path=" + path : "")
        + ((domain) ? "; domain=" + domain : "")
        + ((secure) ? "; secure" : "");
}

// read cookie
function getCookie(name) {
    var cookie = " " + document.cookie;
    var search = " " + name + "=";
    var setStr = null;
    var offset = 0;
    var end = 0;
    if (cookie.length > 0) {
        offset = cookie.indexOf(search);
        if (offset != -1) {
            offset += search.length;
            end = cookie.indexOf(";", offset)
            if (end == -1) {
                end = cookie.length;
            }
            setStr = unescape(cookie.substring(offset, end));
        }
    }
    return(setStr);
}

// check if value empty, null or undefined
function isEmpty(_value) {
    return !(_value);
}

// message bundle
function localMsg(nameVarWithLocalizationMsg,sysnameMsg){
    return eval(nameVarWithLocalizationMsg + '.' + sysnameMsg);
}