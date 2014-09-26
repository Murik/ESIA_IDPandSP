// const not supported in IE8
var reqDsPluginVersion = '2.0.3.1';

function LoginViewModel(_errorCode, _challenge, _idType, _username, _saveId) {
    // IE8 does not support the key const
    var RESULT_OK = "0";
    var MSG_KEY_ID_NAME_PREFIX = "authn.authn.label.";
    var MSG_KEY_VALIDATION_PREFIX = "authn.validation.msg.";
    var MSG_KEY_PWD_EMPTY = MSG_KEY_VALIDATION_PREFIX + "pwd.empty";
    var COOKIE_ID_NAME = "_idp_authn_id";
    var COOKIE_ID_PATH = "/idp";

    var MONTH = 1000 * 60 * 60 * 24 * 30;
    var ID_TYPE_SNILS = "snils";
    var ID_TYPE_PHONE = "phone";
    var ID_TYPE_EMAIL = "email";
    var ID_TYPES = [ID_TYPE_PHONE,ID_TYPE_EMAIL,ID_TYPE_SNILS];
    var EMAIL_PATTERN = /^\s*[\w\-\+_]+(\.[\w\-\+_]+)*@[\w\-\+_]+\.[\w\-\+_]+(\.[\w\-\+_]+)*\s*$/;
    //////
    var self = this;
    var modality;

    // id of active authn type record
    self.index = ko.observable(_indexOf(ID_TYPE_PHONE));

    // array of possible authn type records
    self.ids =  ko.utils.arrayMap(ID_TYPES, function(_type) {
        return {
            id: _indexOf(_type) ,
            typ : _type,
            typeInput: _typeOf(_type),
            val: ko.observable(""),
            msg: ko.observable(""),
            msgVisible: ko.observable(false),
            nam: localMsg('jsonLocalizationMsg', MSG_KEY_ID_NAME_PREFIX + _type) };
    });
    // password record
    self.pwd = {val: ko.observable(""), msg: ko.observable(""), msgVisible: ko.observable(false)};
    // save id checkbox
    self.saveId = ko.observable(false);
    // authn error message
    self.error = {msg: ko.observable(""), msgVisible: ko.observable(false)};

    _init(_errorCode,_challenge, _idType, _username, _saveId);

    // change id
    self.changeId = function(_id) {
        if (_isValidType(_id.typ)) {
            self.index(_id.id);
        }
    };

    // clear cookie
    self.clearIdCookieWhenUnchecked = function() {
        if (!self.saveId()) {
            _clearCookie(COOKIE_ID_NAME, COOKIE_ID_PATH);
        }
        return true;

    };

    function failedDs(data) {
        afterDs();
    }


    self.loginByDs = function() {
        self.error.msg("");
        self.error.msgVisible(false);
        beforeDs();
        dsWidget.check_plugin(sign, failedDs, reqDsPluginVersion);
    }

    function sign() {
        dsWidget.select_and_sign(_challenge,
            function(data) {
                _submitDsForm(data.sign)
            }, failedDs);
    }

    function failedDs(data) {
        afterDs();
    }

    // login
    self.loginByPwd = function() {
        // update password after auto-fill/password feature
        self.pwd.val($("#password").val());
        _showLoading();
        self.error.msg("");
        self.error.msgVisible(false);
        var _input_OK = true;
        // id validation
//        var _msgCode = _validateValue(_curId().typ, _curId().val());
//        if (_msgCode != RESULT_OK) {
//            _input_OK = false;
//            _curId().msg(localMsg('jsonLocalizationMsg', _msgCode));
//            _curId().msgVisible(true);
//        } else {
//            _curId().msg("");
//            _curId().msgVisible(false);
//        }
        // pwd validation
        if (isEmpty(self.pwd.val())) {
            _input_OK = false;
            self.pwd.msg(localMsg('jsonLocalizationMsg',MSG_KEY_PWD_EMPTY));
            self.pwd.msgVisible(true);
        } else {
            self.pwd.msg("");
            self.pwd.msgVisible(false);
        }
        if (_input_OK){
            if (self.saveId()) {
                _saveIdCookie();
            }
            _submitPwdForm();
        }
        _hideLoading()
    };

    // active authn type record
    function _curId() {
        return self.ids[self.index()];
    }

    // submit login form
    function _submitPwdForm() {
//        var _username = _curId().val();
//        if (_curId().typ == ID_TYPE_PHONE) {
//            _username = _username.replace(/-/g,'').replace(/ /g,'');
//        }
//        $('#idType').val(_curId().typ);
//        $('#username').val(_username);
        $('#login').submit();
    }

    // submit ds form
    function _submitDsForm(_signature) {
        $("#challenge").val(_challenge);
        $("#signature").val(_signature);
        afterDs();
        $('#dsFrm').submit();
    }

    // save active id type and value in cookie with expiration by month
    function _saveIdCookie() {
        setCookie(COOKIE_ID_NAME, _curId().typ + ":" + encodeURIComponent(_curId().val()), COOKIE_ID_PATH, '' ,MONTH)
    }

    // clear cookie
    function _clearCookie(_name,_path) {
        setCookie(_name,"", _path, '', 0);
    }

    // Initialization
    function _init (_errorCode,_challenge,_idType,_idValue, _saveId) {
        if (_errorCode) {
            self.error.msg(localMsg('jsonLocalizationMsg',_errorCode));
            self.error.msgVisible(true);
            _initLogin(_idType,_idValue);
            self.saveId(_saveId);
        } else {
            // read cookie
            var _id_cookie = decodeURIComponent(getCookie(COOKIE_ID_NAME));
            if (_id_cookie) {
                var _idParts = _id_cookie.split(":",2);
                if (_idParts.length == 2){
                    _initLogin(_idParts[0],_idParts[1]);
                    self.saveId(true);
                }
            }
        }

    }

    // Initialization
    function _initLogin (_idType,_idValue) {
        if (_isValidId(_idType,_idValue)) {
            self.index(_indexOf(_idType));
            _curId().val(_idValue);
        }

    }


    // validate id type and value
    function _isValidId(_type, _value) {
        return (_isValidType(_type) && _validateValue(_type,_value) == RESULT_OK)
    }

    // validate id type
    function _isValidType(_type) {
        return (_indexOf(_type)  != -1);
    }

    // validate id value
    function _validateValue(_type, _value) {
        if (isEmpty(_value)) {
            return MSG_KEY_VALIDATION_PREFIX +  _type + ".empty"
        }
        switch (_type) {
            case ID_TYPE_EMAIL:
                if(!EMAIL_PATTERN.test(_value)) {
                    return MSG_KEY_VALIDATION_PREFIX +  _type + ".invalid";
                }
                break;
        }
        return RESULT_OK;
    }

    // get index of authn type record with given type
    function _indexOf(_type) {
        return $.inArray(_type,ID_TYPES);
    }

    // get index of authn type record with given type
    function _typeOf(_type) {
        switch (_type) {
            case ID_TYPE_PHONE:
                return "tel";
            case ID_TYPE_SNILS:
                return "tel";
        }
        return "text";
    }

    // shadow
    function _enableModality()  {
        modality = $('<div class="window-overlay"></div>').appendTo(document.body);

    }
    function _disableModality() {
        modality.remove();
        modality = null;
    }

    // loading
    function _showLoading() {
        _enableModality();
        $('#dialogLoading').show();
    }
    function _hideLoading() {
        _disableModality();
        $('#dialogLoading').hide();
    }

    self.presetLogin = function(_username){
        self.index(_indexOf(ID_TYPE_SNILS));
        _initLogin(ID_TYPE_SNILS,_username);
    }

}










