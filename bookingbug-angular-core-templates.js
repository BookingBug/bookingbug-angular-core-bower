angular.module("BB").run(["$templateCache", function($templateCache) {$templateCache.put("accordion-group.html","<div\n  ng-attr-tabindex=\"{{$parent.has_availability ? 0 : -1}}\"\n  role=\"tab\"\n  id=\"{{::headingId}}\"\n  aria-selected=\"{{isOpen}}\"\n  class=\"panel-heading\"\n  ng-click=\"toggleOpen()\"\n  ng-keypress=\"toggleOpen()\">\n  <h4 class=\"panel-title\">\n    <div\n      role=\"button\"\n      data-toggle=\"collapse\"\n      aria-expanded=\"{{isOpen}}\"\n      aria-controls=\"{{::panelId}}\"\n      class=\"accordion-toggle\"\n      uib-accordion-transclude=\"heading\"\n      ng-disabled=\"isDisabled\">\n      <span uib-accordion-header ng-class=\"{\'text-muted\': isDisabled}\">{{heading}}</span>\n    </div>\n  </h4>\n</div>\n<div\n  id=\"{{::panelId}}\"\n  aria-labelledby=\"{{::headingId}}\"\n  aria-hidden=\"{{!isOpen}}\"\n  role=\"tabpanel\"\n  class=\"panel-collapse collapse\"\n  uib-collapse=\"!isOpen\">\n  <div class=\"panel-body\" ng-transclude></div>\n</div>");
$templateCache.put("bb_date_time_picker.html","<div class=\"row bb-date-picker\">\n  \n    \n  <div ng-class=\"{\n      \'col-xs-5\': dateReadonly,    \n      \'col-xs-7\': !dateOnly && !dateReadonly, \n      \'col-xs-12\': dateOnly\n    }\" \n    ng-hide=\"timeDurationHelper\">\n    \n    <div class=\"input-group\" ng-hide=\"dateReadonly\">\n      <input \n        type=\"text\" \n        ng-model=\"datetimeWithNoTz\" \n        class=\"form-control\"\n        uib-datepicker-popup=\"{{format}}\"\n        is-open=\"opened\"\n        datepicker-options=\"{\'startingDay\': 1, \'showButtonBar\': false, \'showWeeks\': false, \'maxDate\': maxDateClean, \'minDate\': minDateClean}\"\n        show-button-bar=\"false\"\n        ng-class=\"{\'datepicker-show-focus\': opened}\"\n        ng-disabled=\"bbDisabled\"\n        ng-readonly=\"true\"\n        ng-blur=\"opened = false\"\n        ng-keypress=\"$event.keyCode === 13 && (opened = true)\"\n      />\n\n      <span class=\"input-group-btn\" ng-click=\"$event.preventDefault(); $event.stopPropagation(); opened=!opened;\">\n        <button class=\"btn btn-default\" title=\"Select date\">\n          <span class=\"fa fa-calendar\"></span>\n        </button>\n      </span>\n    </div>\n    \n    <div class=\"input-group\" ng-show=\"dateReadonly\">\n      <p class=\"block-time-selection__label\">{{ date | datetime: \'DD/MM/YYYY\' }}</p>\n    </div>\n    \n  </div>\n  \n  <div class=\"col-xs-7\" ng-show=\"timeDurationHelper\">\n    <select class=\"form-control\"\n      name=\"duration\"\n      id=\"duration\"    \n      ng-options=\"duration as duration.label disable when duration.disabled for duration in durations\"\n      ng-model=\"currentDuration\"\n      ng-change=\"onDurationHelperChanged();\">\n    </select>\n    \n  </div>\n  \n  <div class=\"col-xs-5\" ng-show=\"!dateOnly\">\n    <div \n      uib-timepicker \n      template-url=\"timepicker.html\"\n      ng-model=\"datetimeWithNoTz\" \n      show-meridian=\"showMeridian\"\n      minute-step=\"minuteStep\"\n      max=\"maxDateClean\" \n      min=\"minDateClean\" \n      readonly-input=\"true\">\n    </div>\n  </div>\n</div>\n");
$templateCache.put("bootstrap_ui_datetime_form.html","<div class=\"form-group\" ng-class=\"{\'has-error\': hasError(), \'has-success\': !hasError()}\">\n  <label class=\"control-label\">{{form.title}}</label>\n  <input ng-if=\"form.readonly\" ng-show=\"form.key\" type=\"text\" placeholder=\"\" class=\"form-control\" id=\"datetime\"\n         value=\"{{model.datetime  | datetime: \'llll\': true}}\" ng-disabled=\"form.readonly\" name=\"datetime\"\n         disabled=\"disabled\"/>\n  <div class=\"input-group\" ng-if=\"!form.readonly\">\n    <div bb-date-time-picker date=\"$$value$$\" bb-disabled=\"form.readonly\"></div>\n  </div>\n\n  <span class=\"help-block\">{{ (hasError() && errorMessage(schemaError())) || form.description}}</span>\n</div>\n");
$templateCache.put("bootstrap_ui_phonenumber_form.html","<div class=\"form-group\" ng-class=\"{\'has-error\': hasError(), \'has-success\': !hasError()}\">\n  <label class=\"control-label\">{{form.title}}</label>\n  <input bb-int-tel-number=\"form.options\" ng-model=\"$$value$$\"\n  prefix=\"model[\'{{form.key[0]}}_prefix\']\" bb-disabled=\"form.readonly\" class=\"form-control\"\n  type=\"tel\" schema-validate=\"form\"></input>\n\n  <span class=\"help-block\">{{ (hasError() && errorMessage(schemaError())) || form.description}}</span>\n</div>\n");
$templateCache.put("bootstrap_ui_time_form.html","<div class=\"form-group\" ng-class=\"{\'has-error\': hasError()}\">\n  <label class=\"control-label\" ng-show=\"showTitle()\">{{form.title}}</label>\n\n  <div uib-timepicker ng-model=\"$$value$$\" show-meridian=\"false\"></div>\n\n  <span class=\"help-block\">{{ (hasError() && errorMessage(schemaError())) || form.description}}</span>\n</div>\n");
$templateCache.put("date_form.html","<div class=\"form-group\" ng-class=\"{\'has-error\': hasError()}\">\n  <label class=\"control-label\" ng-show=\"showTitle()\">{{form.title}}</label>\n\n  <input ng-if=\"form.readonly\" ng-show=\"form.key\" type=\"text\" placeholder=\"\" class=\"form-control\" id=\"datetime\"\n         value=\"{{model.datetime  | datetime: \'LL\'}}\" ng-disabled=\"form.readonly\" name=\"datetime\" disabled=\"disabled\"/>\n\n  <p class=\"input-group\" ng-if=\"!form.readonly\">\n  <div bb-date-time-picker date-only=\"true\" date=\"$$value$$\"></div>\n  </p>\n\n  <span class=\"help-block\">{{ (hasError() && errorMessage(schemaError())) || form.description}}</span>\n</div>\n");
$templateCache.put("dialog.html","<div class=\"modal-header\">\n  <h3 class=\"modal-title\">{{title}}</h3>\n</div>\n<div class=\"modal-body\">{{body}}</div>\n<div class=\"modal-footer\">\n  <button class=\"btn btn-primary\" ng-click=\"ok()\"><span translate=\"COMMON.BTN.YES\"></span></button>\n  <button class=\"btn btn-default\" ng-click=\"cancel()\"><span translate=\"COMMON.BTN.NO\"></span></button>\n</div>\n");
$templateCache.put("file_upload.html","<!-- label -->\n<label for=\"file_upload\" class=\"control-label col-sm-4\">\n  File upload:\n  <p ng-show=\"maxSize\">should be smaller then {{maxSize}}</p>\n</label>\n\n<div class=\"col-sm-5\">\n\n  <!-- upload button -->\n  <button\n    type=\"file\"\n    class=\"btn btn-secondary\"\n    ngf-max-size=\"{{maxSize}}\"\n    ngf-accept=\"{{accept}}\"\n    ngf-model-invalid=\"errorFile\"\n    ngf-select=\"uploadFile(item, $file, $invalidFiles, item.attachment_id, item.attachment_uuid)\">\n    Select File\n  </button>\n\n  <!-- progress -->\n  <div class=\"progress\"\n       ng-show=\"my_file.progress >= 0 && my_file.progress < 100\">\n    <div\n      class=\"progress-bar\"\n      role=\"progressbar\"\n      aria-valuenow=\"{{my_file.progress}}\"\n      aria-valuemin=\"0\"\n      aria-valuemax=\"100\"\n      style=\"width:{{my_file.progress}}%\">\n    </div>\n  </div>\n\n  <!-- attachment -->\n  <div ng-if=\"item.attachment_uuid || item.attachment_id\">\n    Currently uploaded file:\n    <a ng-href=\"{{item.getAttachment().url}}\">\n      {{my_file.name}}\n    </a>\n    <span class=\"btn btn-link\" ng-click=\"item.deleteAttachment() && clearFileInput()\">\n      <i class=\"fa fa-times\"></i>\n      <span class=\"sr-only\">Delete</span>\n    </span>\n  </div>\n\n</div>\n\n<!-- messages -->\n<div class=\"col-sm-3 messages\">\n  <p class=\"text-danger\" ng-show=\"show_error\">\n    Upload failed\n  </p>\n  <p class=\"text-danger\" ng-show=\"err_file\">\n    The file should be no bigger than {{err_file.$errorParam}}\n  </p>\n  <p class=\"text-danger\" ng-show=\"file_type_error\">\n    The file must be one the following file types: <b>{{prettyAccept}}</b>\n  </p>\n</div>\n\n");
$templateCache.put("modal_form.html","<div class=\"modal-header\">\n  <h3 class=\"modal-title\">{{title}}</h3>\n</div>\n<form\n  name=\"modal_form\"\n  ng-submit=\"submit(modal_form)\">\n  <div\n    ng-show=\"loading\"\n    class=\"loader\"></div>\n  <div\n    class=\"modal-body\"\n    sf-schema=\"schema\"\n    sf-form=\"form\"\n    sf-model=\"form_model\"\n    sf-options=\"{formDefaults: {feedback: false}}\"\n    ng-hide=\"loading\">\n  </div>\n  <div class=\"modal-footer\">\n    <button\n      type=\"submit\"\n      class=\"btn btn-primary\"\n      ng-disabled=\"loading\"\n      translate=\"CORE.SCHEMA_FORM.OK_BTN\">\n    </button>\n    <button\n      type=\"button\"\n      class=\"btn btn-default\"\n      ng-click=\"cancel($event)\"\n      translate=\"CORE.SCHEMA_FORM.CANCEL_BTN\">\n    </button>\n  </div>\n</form>\n");
$templateCache.put("price_form.html","<div class=\"form-group\" ng-class=\"{\'has-error\': hasError()}\">\n  <label class=\"control-label\" ng-show=\"showTitle()\">{{form.title}}</label>\n\n  <div pricepicker ng-model=\"$$value$$\" currency=\"{{form.currency}}\"></div>\n\n  <span class=\"help-block\">{{ (hasError() && errorMessage(schemaError())) || form.description}}</span>\n</div>\n");
$templateCache.put("radio-buttons.html","<div class=\"form-group schema-form-radiobuttons {{form.htmlClass}}\"\n     ng-class=\"{\'has-error\': hasError(), \'has-success\': hasSuccess()}\">\n  <div>\n    <label class=\"control-label\" ng-show=\"showTitle()\">{{form.title}}</label>\n  </div>\n  <div class=\"btn-group\">\n    <label\n      class=\"btn {{ (item.value === $$value$$) ? form.style.selected || \'btn-default\' : form.style.unselected || \'btn-default\'; }}\"\n      ng-class=\"{ active: item.value === $$value$$ }\"\n      ng-repeat=\"item in form.titleMap\">\n      <input type=\"radio\"\n             class=\"{{form.fieldHtmlClass}}\"\n             sf-changed=\"form\"\n             style=\"display: none;\"\n             ng-disabled=\"form.readonly\"\n             ng-model=\"$$value$$\"\n             ng-model-options=\"form.ngModelOptions\"\n             ng-value=\"item.value\"\n             name=\"{{form.key.join(\'.\')}}\">\n      <span ng-bind-html=\"item.name\"></span>\n    </label>\n  </div>\n  <div class=\"help-block\" ng-show=\"form.description\" ng-bind-html=\"form.description\"></div>\n</div>\n");
$templateCache.put("radios-inline.html","<div class=\"form-group schema-form-radios-inline {{form.htmlClass}}\"\n     ng-class=\"{\'has-error\': hasError(), \'has-success\': hasSuccess()}\">\n  <label class=\"control-label\" ng-show=\"showTitle()\">{{form.title}}</label>\n  <div>\n    <label class=\"radio-inline\" ng-repeat=\"item in form.titleMap\">\n      <input type=\"radio\"\n             class=\"{{form.fieldHtmlClass}}\"\n             sf-changed=\"form\"\n             ng-disabled=\"form.readonly\"\n             ng-model=\"$$value$$\"\n             ng-value=\"item.value\"\n             name=\"{{form.key.join(\'.\')}}\">\n      <span ng-bind-html=\"item.name\"></span>\n    </label>\n  </div>\n  <div class=\"help-block\" ng-show=\"(hasError() && errorMessage(schemaError())) || form.description\"\n       ng-bind-html=\"(hasError() && errorMessage(schemaError())) || form.description\"></div>\n</div>\n");
$templateCache.put("radios.html","<div class=\"form-group schema-form-radios {{form.htmlClass}}\"\n     ng-class=\"{\'has-error\': hasError(), \'has-success\': hasSuccess()}\">\n  <label class=\"control-label\" ng-show=\"showTitle()\">{{form.title}}</label>\n  <div class=\"radio\" ng-repeat=\"item in form.titleMap\">\n    <label>\n      <input type=\"radio\"\n             class=\"{{form.fieldHtmlClass}}\"\n             sf-changed=\"form\"\n             ng-disabled=\"form.readonly\"\n             ng-model=\"$$value$$\"\n             ng-model-options=\"form.ngModelOptions\"\n             ng-value=\"item.value\"\n             name=\"{{form.key.join(\'.\')}}\">\n      <span ng-bind-html=\"item.name\"></span>\n    </label>\n  </div>\n  <div class=\"help-block\" ng-show=\"(hasError() && errorMessage(schemaError())) || form.description\"\n       ng-bind-html=\"(hasError() && errorMessage(schemaError())) || form.description\"></div>\n</div>\n");
$templateCache.put("timepicker.html","<table class=\"uib-timepicker\">\n  <tbody>\n    <tr class=\"text-center\" ng-show=\"::showSpinners\">\n      <td class=\"uib-increment hours\">\n        <a ng-click=\"incrementHours()\" \n          ng-class=\"{disabled: noIncrementHours()}\" \n          class=\"btn btn-link\" \n          ng-disabled=\"noIncrementHours()\" \n          tabindex=\"-1\">\n          <span class=\"glyphicon glyphicon-chevron-up\"></span>\n        </a>\n      </td>\n      <td>&nbsp;</td>\n      <td class=\"uib-increment minutes\">\n        <a ng-click=\"incrementMinutes()\" \n          ng-class=\"{disabled: noIncrementMinutes()}\" \n          class=\"btn btn-link\" \n          ng-disabled=\"noIncrementMinutes()\" \n          tabindex=\"-1\">\n          <span class=\"glyphicon glyphicon-chevron-up\"></span>\n        </a>\n      </td>\n      <td ng-show=\"showSeconds\">&nbsp;</td>\n      <td ng-show=\"showSeconds\" class=\"uib-increment seconds\">\n        <a ng-click=\"incrementSeconds()\" \n          ng-class=\"{disabled: noIncrementSeconds()}\" \n          class=\"btn btn-link\" \n          ng-disabled=\"noIncrementSeconds()\" \n          tabindex=\"-1\">\n          <span class=\"glyphicon glyphicon-chevron-up\"></span>\n        </a>\n      </td>\n      <td ng-show=\"showMeridian\"></td>\n    </tr>\n    <tr>\n      <td class=\"form-group uib-time hours\" ng-class=\"{\'has-error\': invalidHours}\">\n        <input type=\"text\" \n          placeholder=\"HH\" \n          ng-model=\"hours\" \n          ng-change=\"updateHours()\" \n          class=\"form-control text-center\" \n          ng-readonly=\"::readonlyInput\" \n          maxlength=\"2\" \n          tabindex=\"{{::tabindex}}\" \n          ng-disabled=\"noIncrementHours() && noDecrementHours()\" \n          ng-blur=\"blur()\">\n      </td>\n      <td class=\"uib-separator\">:</td>\n      <td class=\"form-group uib-time minutes\" ng-class=\"{\'has-error\': invalidMinutes}\">\n        <input type=\"text\" \n          placeholder=\"MM\" \n          ng-model=\"minutes\" \n          ng-change=\"updateMinutes()\" \n          class=\"form-control text-center\" \n          ng-readonly=\"::readonlyInput\" \n          maxlength=\"2\" \n          tabindex=\"{{::tabindex}}\" \n          ng-disabled=\"noIncrementMinutes() && noDecrementMinutes()\" \n          ng-blur=\"blur()\">\n      </td>\n      <td ng-show=\"showSeconds\" class=\"uib-separator\">:</td>\n      <td class=\"form-group uib-time seconds\" ng-class=\"{\'has-error\': invalidSeconds}\" ng-show=\"showSeconds\">\n        <input type=\"text\" \n          placeholder=\"SS\" \n          ng-model=\"seconds\" \n          ng-change=\"updateSeconds()\" \n          class=\"form-control text-center\" \n          ng-readonly=\"readonlyInput\" \n          maxlength=\"2\" \n          tabindex=\"{{::tabindex}}\" \n          ng-disabled=\"noIncrementSeconds()\" \n          ng-blur=\"blur()\">\n      </td>\n      <td ng-show=\"showMeridian\" class=\"uib-time am-pm\">\n        <button type=\"button\" \n          ng-class=\"{disabled: noToggleMeridian()}\" \n          class=\"btn btn-default text-center\" \n          ng-click=\"toggleMeridian()\" \n          ng-disabled=\"noToggleMeridian()\" \n          tabindex=\"{{::tabindex}}\">{{meridian}}</button>\n        </td>\n    </tr>\n    <tr class=\"text-center\" ng-show=\"::showSpinners\">\n      <td class=\"uib-decrement hours\">\n        <a ng-click=\"decrementHours()\" \n          ng-class=\"{disabled: noDecrementHours()}\" \n          class=\"btn btn-link\" \n          ng-disabled=\"noDecrementHours()\" \n          tabindex=\"-1\">\n          <span class=\"glyphicon glyphicon-chevron-down\"></span>\n        </a>\n      </td>\n      <td>&nbsp;</td>\n      <td class=\"uib-decrement minutes\">\n        <a ng-click=\"decrementMinutes()\" \n          ng-class=\"{disabled: noDecrementMinutes()}\" \n          class=\"btn btn-link\" \n          ng-disabled=\"noDecrementMinutes()\" \n          tabindex=\"-1\">\n          <span class=\"glyphicon glyphicon-chevron-down\"></span>\n        </a>\n      </td>\n      <td ng-show=\"showSeconds\">&nbsp;</td>\n      <td ng-show=\"showSeconds\" class=\"uib-decrement seconds\">\n        <a ng-click=\"decrementSeconds()\" \n          ng-class=\"{disabled: noDecrementSeconds()}\" \n          class=\"btn btn-link\" \n          ng-disabled=\"noDecrementSeconds()\" \n          tabindex=\"-1\">\n          <span class=\"glyphicon glyphicon-chevron-down\"></span>\n        </a>\n      </td>\n      <td ng-show=\"showMeridian\"></td>\n    </tr>\n  </tbody>\n</table>");
$templateCache.put("i18n/_bb_timezone_select.html","<div class=\"form-group toggle-container\" ng-if=\"!$bbTimeZoneSelectCtrl.hideToggle\">\n  <label>\n    <span tabindex=\"0\" translate=\"I18N.TIMEZONE.SET_TIMEZONE_AUTOMATICALLY_LABEL\"></span>\n  </label>\n  <toggle-switch\n    ng-change=\"$bbTimeZoneSelectCtrl.automaticTimeZoneToggle()\"\n    ng-model=\"$bbTimeZoneSelectCtrl.isAutomaticTimeZone\"\n    on-label=\"{{\'I18N.TIMEZONE.SET_TIMEZONE_AUTOMATICALLY_ON_LABEL\' | translate}}\"\n    off-label=\"{{\'I18N.TIMEZONE.SET_TIMEZONE_AUTOMATICALLY_OFF_LABEL\' | translate}}\"\n    class=\"switch-primary\">\n  </toggle-switch>\n</div>\n\n<div class=\"form-group\">\n  <label>\n    <span tabindex=\"0\" translate=\"I18N.TIMEZONE.TIMEZONE_LABEL\"></span>\n  </label>\n  \n  <!-- Standard ui-select -->\n  <ui-select\n    ng-if=\"!$bbTimeZoneSelectCtrl.isLongList\"\n    ng-model=\"$bbTimeZoneSelectCtrl.selectedTimeZone\"\n    theme=\"bootstrap\"\n    ng-disabled=\"$bbTimeZoneSelectCtrl.isAutomaticTimeZone\"\n    ng-change=\"$bbTimeZoneSelectCtrl.setTimeZone($bbTimeZoneSelectCtrl.selectedTimeZone.value);\">\n\n    <ui-select-match placeholder=\"{{\'I18N.TIMEZONE.SELECT_TIMEZONE_PLACEHOLDER\' | translate}}\">\n      {{$select.selected.display}}\n    </ui-select-match>\n\n    <ui-select-choices\n      ui-select-choices-listener\n      refresh-delay=\"0\"\n      repeat=\"\n        timezone as timezone in $bbTimeZoneSelectCtrl.timeZones |\n        props: { display: $select.search}\n        track by timezone.id\">\n      <div ng-bind-html=\"timezone.display | highlight: $select.search\"></div>\n    </ui-select-choices>\n  </ui-select>      \n  \n  <!-- Using ui-select-choices-lazyload due to perfomance issues with big lists -->\n  <ui-select\n    ng-if=\"$bbTimeZoneSelectCtrl.isLongList\"\n    ng-model=\"$bbTimeZoneSelectCtrl.selectedTimeZone\"\n    theme=\"bootstrap\"\n    ng-disabled=\"$bbTimeZoneSelectCtrl.isAutomaticTimeZone\"\n    ng-change=\"$bbTimeZoneSelectCtrl.setTimeZone($bbTimeZoneSelectCtrl.selectedTimeZone.value);\">\n\n    <ui-select-match placeholder=\"{{\'I18N.TIMEZONE.SELECT_TIMEZONE_PLACEHOLDER\' | translate}}\">\n      {{$select.selected.display}}\n    </ui-select-match>\n\n    <ui-select-choices\n      ui-select-choices-lazyload\n      all-choices=\"$bbTimeZoneSelectCtrl.timeZones\"\n      refresh-delay=\"0\"\n      repeat=\"\n        timezone as timezone in $select.pagingOptions.items |\n        props: { display: $select.search}\n        track by timezone.id\n      \">\n      <div ng-bind-html=\"timezone.display | highlight: $select.search\"></div>\n    </ui-select-choices>\n  </ui-select>    \n</div>\n");
$templateCache.put("i18n/language_picker.html","\n<a uib-dropdown-toggle href=\"#\" class=\"dropdown-toggle\">\n  {{ vm.language.selected.label | translate }} <span class=\"caret\"></span>\n</a>\n<ul uib-dropdown-menu class=\"dropdown-menu\" role=\"menu\">\n  <li role=\"menuitem\" ng-repeat=\"lang in vm.availableLanguages\">\n    <a ng-click=\"vm.setLanguage(lang)\" href=\"#\">{{lang.label | translate}}</a>\n  </li>\n</ul>\n");}]);