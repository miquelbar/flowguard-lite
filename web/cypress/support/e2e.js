Cypress.Commands.add("assertNoDocumentHorizontalOverflow", () => {
    cy.window().then((win) => {
        const doc = win.document.documentElement;
        const body = win.document.body;
        const allowed = 2;

        expect(doc.scrollWidth, "document width").to.be.at.most(doc.clientWidth + allowed);
        expect(body.scrollWidth, "body width").to.be.at.most(body.clientWidth + allowed);
    });
});

Cypress.Commands.add("assertVisibleView", (viewID) => {
    cy.get(`#${viewID}`).should("have.class", "active").and("be.visible");
});

Cypress.Commands.add("assertElementDoesNotWidenDocument", (selector) => {
    cy.get(selector).then(($el) => {
        const rect = $el[0].getBoundingClientRect();
        const viewportWidth = $el[0].ownerDocument.documentElement.clientWidth;
        expect(rect.left, `${selector} left edge`).to.be.at.least(-2);
        expect(rect.right, `${selector} right edge`).to.be.at.most(viewportWidth + 2);
    });
});

beforeEach(() => {
    cy.intercept('**', (req) => {
        req.on('response', (res) => {
            res.headers['cache-control'] = 'no-cache, no-store, must-revalidate';
            res.headers['pragma'] = 'no-cache';
            res.headers['expires'] = '0';
        });
    });
});
