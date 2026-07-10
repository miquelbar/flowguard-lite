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
