<#import "template.ftl" as layout>
<@layout.registrationLayout; section>
    <#if section = "header">
        ${msg("smsTypeOTPFromSms")}
    <#elseif section = "form">
        <form id="kc-otp-sms-login-form" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">
            <div class="${properties.kcFormGroupClass!}">
                <div class="${properties.kcLabelWrapperClass!}">
                    <label for="otp-sms" class="${properties.kcLabelClass!}">${msg("typeCodeFromSms")}</label>
                </div>

                <div class="${properties.kcInputWrapperClass!}">
                    <input id="otp-sms" name="sms_code" type="text" class="${properties.kcInputClass!}" />
                </div>
            </div>

            <div class="${properties.kcFormGroupClass!}">
                <div id="kc-form-options" class="${properties.kcFormOptionsClass!}">
                    <div class="${properties.kcFormOptionsWrapperClass!}">
                    </div>
                </div>

                <div id="kc-form-buttons" class="${properties.kcFormButtonsClass!}">
                    <div class="${properties.kcFormButtonsWrapperClass!}">
                        <input class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonLargeClass!}" name="login" id="kc-login" type="submit" value="${msg("doLogIn")}"/>
                        <input class="${properties.kcButtonClass!} ${properties.kcButtonLargeClass!}" name="cancel" id="kc-cancel" type="button" onClick="location.href='${url.loginRestartFlowUrl}'" value="${msg("doCancel")}"/>
                    </div>
                </div>
            </div>
        </form>
    </#if>
</@layout.registrationLayout>