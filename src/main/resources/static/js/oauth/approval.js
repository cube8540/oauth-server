const SCOPE_FORM_ID = 'scope-form';
const CSRF_ATTRIBUTE_NAME = '_csrf';

function approvalOrDeny(approvalOrDeny) {
    const $form = document.getElementById(SCOPE_FORM_ID);
    const $inputs = $form.getElementsByTagName('input');
    for (let $input of $inputs) {
        if ($input.getAttribute('name') !== CSRF_ATTRIBUTE_NAME) {
            $input.value = approvalOrDeny;
        }
    }
    $form.submit();
}