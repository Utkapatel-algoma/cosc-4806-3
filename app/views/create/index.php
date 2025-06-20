<?php require_once 'app/views/templates/header.php' ?>
<div class="container">
    <h2>Create Account</h2>

    <?php if (!empty($_SESSION['error'])): ?>
        <p style="color:red"><?= $_SESSION['error'] ?></p>
        <?php unset($_SESSION['error']); ?>
    <?php endif; ?>

    <form method="POST" action="/create/register">
        <label>Username: <input type="text" name="username" required></label><br><br>
        <label>Password: <input type="password" name="password" required></label><br><br>
        <button type="submit">Create Account</button>
    </form>

    <p><a href="/login">Back to Login</a></p>
</div>
<?php require_once 'app/views/templates/footer.php' ?>
