document.addEventListener('DOMContentLoaded', function () {
  const addCoauthorBtn = document.getElementById('add-coauthor');
  if (addCoauthorBtn) {
    addCoauthorBtn.addEventListener('click', function (e) {
      e.preventDefault();
      const totalForms = document.getElementById('id_authors-TOTAL_FORMS');
      if (!totalForms) return;
      const formIdx = parseInt(totalForms.value, 10);
      const container = document.getElementById('coauthor-formset');
      const emptyForm = document.getElementById('empty-coauthor-form');
      if (!container || !emptyForm) return;
      const html = emptyForm.innerHTML.replace(/__prefix__/g, formIdx);
      const wrapper = document.createElement('div');
      wrapper.className = 'formset-row';
      wrapper.innerHTML = html;
      container.appendChild(wrapper);
      totalForms.value = formIdx + 1;
    });
  }
});
