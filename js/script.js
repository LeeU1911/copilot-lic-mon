document.addEventListener('DOMContentLoaded', function() {
    // Modal functionality
    const modal = document.getElementById('payment-modal');
    const btn = document.getElementById('subscribe-cta-button');
    const span = document.getElementsByClassName('close')[0];
    const emailForm = document.getElementById('email-form');
    const formSuccess = document.getElementById('form-success');
    
    document.querySelectorAll(".btn-view").forEach(function (btn) {
        btn.addEventListener("click", function () {
          const logId = btn.getAttribute("data-log-id");
          toggleLogDetails(parseInt(logId));
        });
      });
      

    if (btn) {
        btn.onclick = function() {
            modal.style.display = 'block';
        }
    }
    
    if (span) {
        span.onclick = function() {
            modal.style.display = 'none';
        }
    }
    
    window.onclick = function(event) {
        if (event.target == modal) {
            modal.style.display = 'none';
        }
    }
    
    
    if (emailForm) {
        emailForm.onsubmit = function(e) {
            e.preventDefault();
            const email = document.getElementById('user-email').value;
            
            // Here you would typically send the email to your server
            // For now, we'll just show the success message
            emailForm.style.display = 'none';
            formSuccess.style.display = 'block';
            
            // You could add AJAX here to send the email to your server
            // fetch('/save-email.php', {
            //     method: 'POST',
            //     headers: {
            //         'Content-Type': 'application/json',
            //     },
            //     body: JSON.stringify({ email: email }),
            // });
            
            // Hide the modal after 3 seconds
            setTimeout(function() {
                modal.style.display = 'none';
            }, 3000);
        }
    }
    
    // Existing save-now.js functionality
    const saveNowButton = document.getElementById('save-now-button');
    if (saveNowButton) {
        saveNowButton.addEventListener('click', function(e) {
            e.preventDefault();
            const savingsAmount = this.getAttribute('data-savings-amount');
            const csrfToken = this.getAttribute('data-csrf-token');
            
            // Calculate fee amount based on savings
            let feeAmount;
            if (savingsAmount > 500) {
                feeAmount = 100;
            } else if (savingsAmount >= 100) {
                feeAmount = savingsAmount * 0.2;
            } else {
                feeAmount = savingsAmount * 0.4;
            }
            
            // Create and submit the form
            const form = document.createElement('form');
            form.method = 'POST';
            form.action = '';
            
            const csrfInput = document.createElement('input');
            csrfInput.type = 'hidden';
            csrfInput.name = 'csrf_token';
            csrfInput.value = csrfToken;
            
            const saveNowInput = document.createElement('input');
            saveNowInput.type = 'hidden';
            saveNowInput.name = 'save_now';
            saveNowInput.value = '1';
            
            const savingsInput = document.createElement('input');
            savingsInput.type = 'hidden';
            savingsInput.name = 'savings_amount';
            savingsInput.value = savingsAmount;
            
            const feeInput = document.createElement('input');
            feeInput.type = 'hidden';
            feeInput.name = 'fee_amount';
            feeInput.value = feeAmount;
            
            form.appendChild(csrfInput);
            form.appendChild(saveNowInput);
            form.appendChild(savingsInput);
            form.appendChild(feeInput);
            
            document.body.appendChild(form);
            form.submit();
        });
    }
    
    // Function to display errors
    function displayErrors(errors) {
        // Create error summary section
        const errorSummary = document.createElement('div');
        errorSummary.className = 'error-summary';
        errorSummary.innerHTML = `
            <h3>Some seats could not be disabled</h3>
            <p>The following seats could not be disabled due to API errors:</p>
            <table class="error-table">
                <thead>
                    <tr>
                        <th>Username</th>
                        <th>Error</th>
                    </tr>
                </thead>
                <tbody>
                    ${errors.map(error => `
                        <tr>
                            <td>${escapeHtml(error.username)}</td>
                            <td>${escapeHtml(error.error)}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;
        
        // Insert after the savings card
        const savingsCard = document.querySelector('.savings-card');
        if (savingsCard) {
            savingsCard.parentNode.insertBefore(errorSummary, savingsCard.nextSibling);
        }
    }
    
    // Function to update the savings card
    function updateSavingsCard(disabledSeats, totalInactiveSeats) {
        const savingsCard = document.querySelector('.savings-card');
        if (savingsCard) {
            const title = savingsCard.querySelector('h2');
            const amount = savingsCard.querySelector('.savings-amount');
            const description = savingsCard.querySelector('p');
            
            if (title) title.textContent = 'Monthly Savings';
            if (amount) {
                // Calculate the actual savings (assuming $19 per seat)
                const actualSavings = disabledSeats * 19;
                amount.textContent = `$${actualSavings.toFixed(2)}`;
            }
            if (description) {
                description.textContent = `You have a monthly savings of $${(disabledSeats * 19).toFixed(2)} from ${disabledSeats} disabled seats`;
            }
        }
    }
    
    // Helper function to escape HTML
    function escapeHtml(unsafe) {
        return unsafe
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }
    
    // Toggle log details
    function toggleLogDetails(logId) {
        const detailsRow = document.getElementById(`log-details-${logId}`);
        const button = event.currentTarget;
        
        if (detailsRow.style.display === 'none') {
            detailsRow.style.display = 'table-row';
            button.innerHTML = '<i class="bi bi-eye-slash"></i> Hide';
        } else {
            detailsRow.style.display = 'none';
            button.innerHTML = '<i class="bi bi-eye"></i> View';
        }
    }

    // Initialize all log detail rows as hidden
    document.querySelectorAll('.log-details-row').forEach(row => {
        row.style.display = 'none';
    });
});